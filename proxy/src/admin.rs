//! Admin/Management API: JWT auth + Casbin RBAC, powered by axum.
//! Endpoints: login, users CRUD + roles, metrics, quota/self.
//! Runs on a separate port (loopback by default).

use axum::extract::{Path, State};
use axum::Extension;
use axum::http::StatusCode;
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use crate::error::AppError;
use crate::state::AppState;
use crate::token::Claims;
use crate::user_store::{QuotaLimits, UserStore};

// ─── Router ─────────────────────────────────────────────

pub fn admin_router(state: AppState) -> Router {
    // Public routes (no auth)
    let public = Router::new()
        .route("/api/login", post(handle_login))
        .route("/api/health", get(|| async { "ok" }));

    // Authenticated routes (JWT + RBAC middleware)
    let protected = Router::new()
        // Users
        .route("/api/users", get(handle_list_users).post(handle_create_user))
        .route("/api/users/{id}/quota", get(handle_get_quota).put(handle_set_quota))
        .route("/api/users/{id}/passwd", post(handle_passwd))
        .route("/api/users/{id}/disable", post(handle_disable))
        .route("/api/users/{id}/enable", post(handle_enable))
        .route("/api/users/{id}", delete(handle_delete_user))
        .route("/api/roles/{id}", post(handle_set_role))
        // Metrics
        .route("/api/metrics/system", get(handle_metrics_system))
        .route("/api/metrics/users", get(handle_metrics_users))
        .route("/api/metrics/self", get(handle_metrics_self))
        .route("/api/metrics/users/{id}", get(handle_metrics_user))
        // Quota
        .route("/api/quota/self", get(handle_quota_self))
        // Catch-all 404
        .route("/{*anything}", any(|| async { Err::<&str, _>(AppError::NotFound) }))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth_and_rbac,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run_admin_server(state: AppState) -> anyhow::Result<()> {
    let bind = state
        .config
        .auth
        .as_ref()
        .and_then(|a| a.admin.as_ref())
        .map(|a| a.bind.clone())
        .unwrap_or_else(|| "127.0.0.1:8444".into());
    let addr: std::net::SocketAddr = bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("admin_listening addr={}", bind);
    axum::serve(listener, admin_router(state)).await?;
    Ok(())
}

// ─── Store accessor ─────────────────────────────────────

fn store(state: &AppState) -> Result<&Arc<UserStore>, AppError> {
    state
        .store
        .as_ref()
        .ok_or(AppError::Internal(anyhow::anyhow!("no user store")))
}

// ─── Login (public) ─────────────────────────────────────

async fn handle_login(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::bad_request("bad_json"))?;

    let username = parsed.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = parsed.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if username.is_empty() || password.is_empty() {
        return Err(AppError::bad_request("missing_credentials"));
    }

    let store = store(&state)?;
    let tokens = state
        .tokens
        .as_ref()
        .ok_or(AppError::Internal(anyhow::anyhow!("no token manager")))?;
    let rbac = state
        .rbac
        .as_ref()
        .ok_or(AppError::Internal(anyhow::anyhow!("no rbac")))?;

    let user = store
        .get_user(username)
        .await
        .ok()
        .flatten()
        .ok_or(AppError::Unauthorized)?;

    if user.status != "active" || !crate::user_store::verify_password(password, &user.pw_hash) {
        return Err(AppError::Unauthorized);
    }

    let _ = store.record_login(user.id, true).await;
    rbac.assign_role(&user.id.to_string(), &user.role);
    let display = user.display.clone().unwrap_or_else(|| user.username.clone());
    let token = tokens.issue(&user.id.to_string(), &user.role, &display)?;

    info!("login_ok user={} role={}", user.username, user.role);
    Ok(Json(json!({
        "token": token,
        "user": {"id": user.id, "username": user.username, "role": user.role, "display": display},
        "expires_in_days": 30,
    })))
}

// ─── Users CRUD ─────────────────────────────────────────

async fn handle_list_users(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let store = store(&state)?;
    let users = store.list_users().await?;
    let list: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            json!({
                "id": u.id, "username": u.username, "display": u.display,
                "status": u.status, "role": u.role, "note": u.note, "last_login_at": u.last_login_at,
            })
        })
        .collect();
    Ok(Json(list))
}

async fn handle_create_user(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::bad_request("bad_json"))?;
    let username = parsed.get("username").and_then(|v| v.as_str()).unwrap_or("");
    if username.is_empty() {
        return Err(AppError::bad_request("username_required"));
    }
    let display = parsed.get("display").and_then(|v| v.as_str());
    let note = parsed.get("note").and_then(|v| v.as_str());
    let role = parsed.get("role").and_then(|v| v.as_str()).unwrap_or("user");
    let password = crate::user_store::generate_password();

    let store = store(&state)?;
    let user = store
        .create_user(username, &password, display, note)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate") {
                AppError::Conflict("username_exists".into())
            } else {
                AppError::Internal(e)
            }
        })?;

    if role != "user" {
        let _ = store.set_role(user.id, role).await;
    }
    info!("admin_user_create username={username} role={role}");
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": user.id, "username": user.username, "role": role, "password": password,
        })),
    ))
}

async fn handle_get_quota(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    let row = store.get_user_by_id(id).await?.ok_or(AppError::NotFound)?;
    let usage = store.get_usage(id).await.unwrap_or_default();
    Ok(Json(json!({
        "username": row.username, "role": row.role,
        "quota": {
            "req_day": row.quota_req_day, "tok_in": row.quota_tok_in,
            "tok_out": row.quota_tok_out, "bytes_in": row.quota_bytes_in,
            "bytes_out": row.quota_bytes_out,
        },
        "usage_today": {
            "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
            "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
        }
    })))
}

async fn handle_set_quota(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::bad_request("bad_json"))?;
    let q = QuotaLimits {
        quota_req_day: parsed.get("req_day").and_then(|v| v.as_i64()),
        quota_tok_in: parsed.get("tok_in").and_then(|v| v.as_i64()),
        quota_tok_out: parsed.get("tok_out").and_then(|v| v.as_i64()),
        quota_bytes_in: parsed.get("bytes_in").and_then(|v| v.as_i64()),
        quota_bytes_out: parsed.get("bytes_out").and_then(|v| v.as_i64()),
    };
    let store = store(&state)?;
    store.update_quota(id, &q).await?;
    info!("admin_quota_update id={id}");
    Ok(Json(json!({"updated": true})))
}

async fn handle_passwd(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    let password = crate::user_store::generate_password();
    store.set_password(id, &password).await?;
    info!("admin_user_passwd id={id}");
    Ok(Json(json!({"password": password})))
}

async fn handle_disable(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    store.set_status(id, "disabled").await?;
    info!("admin_user_disable id={id}");
    Ok(Json(json!({"status": "disabled"})))
}

async fn handle_enable(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    store.set_status(id, "active").await?;
    info!("admin_user_enable id={id}");
    Ok(Json(json!({"status": "active"})))
}

async fn handle_delete_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    store.delete_user(id).await?;
    if let Some(rbac) = &state.rbac {
        rbac.set_role(&id.to_string(), "");
    }
    info!("admin_user_delete id={id}");
    Ok(Json(json!({"deleted": true})))
}

// ─── Roles ──────────────────────────────────────────────

async fn handle_set_role(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::bad_request("bad_json"))?;
    let role = parsed.get("role").and_then(|v| v.as_str()).unwrap_or("user");
    let store = store(&state)?;
    store.set_role(id, role).await?;
    if let Some(rbac) = &state.rbac {
        rbac.set_role(&id.to_string(), role);
    }
    info!("admin_role_set id={id} role={role}");
    Ok(Json(json!({"updated": true})))
}

// ─── Metrics ────────────────────────────────────────────

async fn handle_metrics_system(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let metrics_text = crate::metrics::render();
    let resp = json!({
        "active_connections": extract_metric(&metrics_text, "ai_proxy_active_connections"),
        "cert_cache_entries": extract_metric(&metrics_text, "ai_proxy_cert_cache_entries"),
        "vault_connected": extract_metric(&metrics_text, "ai_proxy_vault_connected"),
        "prometheus_raw_lines": metrics_text.lines().count(),
    });
    Ok(Json(resp))
}

async fn handle_metrics_users(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let store = store(&state)?;
    let users = store.list_users().await?;
    let mut results = Vec::new();
    for u in &users {
        let usage = store.get_usage_total(u.id).await.unwrap_or_default();
        results.push(json!({
            "username": u.username, "role": u.role, "status": u.status,
            "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
            "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
        }));
    }
    Ok(Json(results))
}

async fn handle_metrics_self(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    let uid: uuid::Uuid = claims.sub.parse().unwrap_or_default();
    let usage = store.get_usage_total(uid).await.unwrap_or_default();
    Ok(Json(json!({
        "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
        "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
    })))
}

async fn handle_metrics_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    let row = store.get_user_by_id(id).await?.ok_or(AppError::NotFound)?;
    let usage = store.get_usage_total(id).await.unwrap_or_default();
    Ok(Json(json!({
        "username": row.username, "role": row.role,
        "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
        "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
    })))
}

// ─── Quota self ─────────────────────────────────────────

async fn handle_quota_self(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = store(&state)?;
    let uid: uuid::Uuid = claims
        .sub
        .parse()
        .map_err(|_| AppError::bad_request("bad_token"))?;
    let row = store.get_user_by_id(uid).await?.ok_or(AppError::NotFound)?;
    let usage = store.get_usage(uid).await.unwrap_or_default();
    Ok(Json(json!({
        "username": row.username, "role": row.role,
        "quota": {
            "req_day": row.quota_req_day, "tok_in": row.quota_tok_in,
            "tok_out": row.quota_tok_out, "bytes_in": row.quota_bytes_in,
            "bytes_out": row.quota_bytes_out,
        },
        "usage_today": {
            "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
            "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
        }
    })))
}

// ─── Helpers ────────────────────────────────────────────

fn extract_metric(text: &str, name: &str) -> i64 {
    for line in text.lines() {
        if !line.starts_with(name) {
            continue;
        }
        if let Some(val) = line.split_whitespace().last() {
            return val.parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_metric_simple() {
        let text = "ai_proxy_requests_total 42\nai_proxy_bytes_total 1024";
        assert_eq!(extract_metric(text, "ai_proxy_requests_total"), 42);
        assert_eq!(extract_metric(text, "ai_proxy_bytes_total"), 1024);
    }

    #[test]
    fn test_extract_metric_missing() {
        let text = "other_metric 100";
        assert_eq!(extract_metric(text, "ai_proxy_requests_total"), 0);
    }

    #[test]
    fn test_extract_metric_empty() {
        assert_eq!(extract_metric("", "anything"), 0);
    }

    #[test]
    fn test_extract_metric_with_labels() {
        let text = r#"ai_proxy_requests_total{method="GET",target="api.openai.com"} 150"#;
        assert_eq!(extract_metric(text, "ai_proxy_requests_total"), 150);
    }

    #[test]
    fn test_extract_metric_non_numeric() {
        let text = "metric abc";
        assert_eq!(extract_metric(text, "metric"), 0);
    }
}
