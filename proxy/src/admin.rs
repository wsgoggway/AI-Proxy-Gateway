//! Admin/Management API: JWT auth + Casbin RBAC.
//! Endpoints: login, users CRUD + roles, metrics, quota/self.
//! Runs on a separate port (loopback by default).

use crate::auth::Auth;
use crate::rbac::Rbac;
use crate::token::{Claims, TokenManager};
use crate::user_store::{QuotaLimits, UserStore};
use anyhow::Context as _;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct AdminServer {
    pub bind: String,
    pub store: Arc<UserStore>,
    pub auth: Option<Arc<Auth>>,
    pub tokens: Arc<TokenManager>,
    pub rbac: Arc<Rbac>,
}

pub async fn run_admin_server(srv: AdminServer) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = srv.bind.parse().context("invalid admin bind")?;
    let listener = TcpListener::bind(addr).await?;
    info!("admin_listening addr={}", srv.bind);

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let store = srv.store.clone();
                let tokens = srv.tokens.clone();
                let rbac = srv.rbac.clone();
                let auth = srv.auth.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let store = store.clone();
                        let tokens = tokens.clone();
                        let rbac = rbac.clone();
                        let auth = auth.clone();
                        async move { route(req, store, tokens, rbac, auth).await }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
            Err(e) => warn!("admin_accept_error error={e}"),
        }
    }
}

// ─── Auth middleware ────────────────────────────────────

fn extract_token(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

async fn authenticate(req: &Request<Incoming>, tokens: &TokenManager) -> Option<Claims> {
    let raw = extract_token(req)?;
    tokens.verify(&raw).ok()
}

// ─── Router ─────────────────────────────────────────────

async fn route(
    req: Request<Incoming>,
    store: Arc<UserStore>,
    tokens: Arc<TokenManager>,
    rbac: Arc<Rbac>,
    _auth: Option<Arc<Auth>>,
) -> Result<Response<String>, hyper::Error> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // ── Public: POST /api/login (no JWT needed) ──
    if method == hyper::Method::POST && path == "/api/login" {
        return handle_login(req, &store, &tokens, &rbac).await;
    }

    // ── All other endpoints require JWT ──
    let claims = match authenticate(&req, &tokens).await {
        Some(c) => c,
        None => {
            return Ok(json(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"unauthorized"}"#,
            ));
        }
    };

    // ── Enforce RBAC ──
    let act = match method {
        hyper::Method::GET => "GET",
        hyper::Method::POST => "POST",
        hyper::Method::PUT => "PUT",
        hyper::Method::DELETE => "DELETE",
        _ => "OTHER",
    };

    if !rbac.enforce(&claims.sub, &path, act) {
        return Ok(json(StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#));
    }

    // ── Route to handlers ──
    match (method.clone(), path.as_str()) {
        // Users
        (hyper::Method::GET, "/api/users") => handle_list_users(&store).await,
        (hyper::Method::POST, "/api/users") => handle_create_user(req, &store).await,
        _ => {
            // /api/users/{id}/{action}
            if let Some(rest) = path.strip_prefix("/api/users/") {
                return handle_user_action(req, rest, &store, &rbac, &claims).await;
            }
            // /api/metrics/*
            if path.starts_with("/api/metrics") {
                return handle_metrics(&path, &store, &claims).await;
            }
            // /api/quota/self
            if path == "/api/quota/self" && method == hyper::Method::GET {
                return handle_quota_self(&store, &claims).await;
            }
            // /api/roles/{id}
            if let Some(rest) = path.strip_prefix("/api/roles/") {
                return handle_set_role(req, rest, &store, &rbac).await;
            }
            Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#))
        }
    }
}

// ─── Login ──────────────────────────────────────────────

async fn handle_login(
    req: Request<Incoming>,
    store: &UserStore,
    tokens: &TokenManager,
    rbac: &Rbac,
) -> Result<Response<String>, hyper::Error> {
    let body = read_body(req).await;
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_json"}"#)),
    };
    let username = parsed
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let password = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if username.is_empty() || password.is_empty() {
        return Ok(json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"missing_credentials"}"#,
        ));
    }

    let user = match store.get_user(username).await {
        Ok(Some(u)) => u,
        _ => {
            return Ok(json(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"invalid_credentials"}"#,
            ));
        }
    };
    if user.status != "active" || !crate::user_store::verify_password(password, &user.pw_hash) {
        return Ok(json(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_credentials"}"#,
        ));
    }
    let _ = store.record_login(user.id, true).await;
    rbac.assign_role(&user.id.to_string(), &user.role);
    let display = user
        .display
        .clone()
        .unwrap_or_else(|| user.username.clone());
    let token = match tokens.issue(&user.id.to_string(), &user.role, &display) {
        Ok(t) => t,
        Err(e) => {
            warn!("token_issue_error error={e}");
            return Ok(json(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"token_failed"}"#,
            ));
        }
    };
    info!("login_ok user={} role={}", user.username, user.role);
    Ok(json(
        StatusCode::OK,
        &serde_json::json!({
            "token": token,
            "user": {"id": user.id, "username": user.username, "role": user.role, "display": display},
            "expires_in_days": 30,
        })
        .to_string(),
    ))
}

// ─── Users CRUD ─────────────────────────────────────────

async fn handle_list_users(store: &UserStore) -> Result<Response<String>, hyper::Error> {
    match store.list_users().await {
        Ok(users) => {
            let list: Vec<serde_json::Value> = users
                .iter()
                .map(|u| {
                    serde_json::json!({
                        "id": u.id,
                        "username": u.username,
                        "display": u.display,
                        "status": u.status,
                        "role": u.role,
                        "note": u.note,
                        "last_login_at": u.last_login_at,
                    })
                })
                .collect();
            Ok(json(StatusCode::OK, &serde_json::json!(list).to_string()))
        }
        Err(e) => Ok(json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{{\"error\":\"{e}\"}}"),
        )),
    }
}

async fn handle_create_user(
    req: Request<Incoming>,
    store: &UserStore,
) -> Result<Response<String>, hyper::Error> {
    let body = read_body(req).await;
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_json"}"#)),
    };
    let username = parsed
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if username.is_empty() {
        return Ok(json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"username_required"}"#,
        ));
    }
    let display = parsed.get("display").and_then(|v| v.as_str());
    let note = parsed.get("note").and_then(|v| v.as_str());
    let role = parsed
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("user");
    let password = crate::user_store::generate_password();
    match store.create_user(username, &password, display, note).await {
        Ok(user) => {
            // Set role (default is 'user' from DB, but allow override)
            if role != "user" {
                let _ = store.set_role(user.id, role).await;
            }
            info!("admin_user_create username={username} role={role}");
            Ok(json(
                StatusCode::CREATED,
                &serde_json::json!({
                    "id": user.id,
                    "username": user.username,
                    "role": role,
                    "password": password,
                })
                .to_string(),
            ))
        }
        Err(e) => {
            let err_str = format!("{e}");
            if err_str.contains("duplicate") {
                Ok(json(StatusCode::CONFLICT, r#"{"error":"username_exists"}"#))
            } else {
                Ok(json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("{{\"error\":\"{e}\"}}"),
                ))
            }
        }
    }
}

async fn handle_user_action(
    req: Request<Incoming>,
    rest: &str,
    store: &UserStore,
    rbac: &Rbac,
    _claims: &Claims,
) -> Result<Response<String>, hyper::Error> {
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 {
        return Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#));
    }
    let id: uuid::Uuid = match parts[0].parse() {
        Ok(i) => i,
        Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_id"}"#)),
    };
    let action = parts[1];
    let method = req.method().clone();

    let user_row = store.get_user_by_id(id).await.ok().flatten();
    let username = user_row.as_ref().map(|u| u.username.clone());

    match (method, action) {
        (hyper::Method::GET, "quota") => {
            let row = match store.get_user_by_id(id).await {
                Ok(Some(r)) => r,
                _ => return Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#)),
            };
            let usage = store.get_usage(id).await.unwrap_or_default();
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({
                    "username": row.username,
                    "role": row.role,
                    "quota": {
                        "req_day": row.quota_req_day, "tok_in": row.quota_tok_in,
                        "tok_out": row.quota_tok_out, "bytes_in": row.quota_bytes_in,
                        "bytes_out": row.quota_bytes_out,
                    },
                    "usage_today": {
                        "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
                        "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
                    }
                })
                .to_string(),
            ))
        }
        (hyper::Method::PUT, "quota") => {
            let body = read_body(req).await;
            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_json"}"#)),
            };
            let q = QuotaLimits {
                quota_req_day: parsed.get("req_day").and_then(|v| v.as_i64()),
                quota_tok_in: parsed.get("tok_in").and_then(|v| v.as_i64()),
                quota_tok_out: parsed.get("tok_out").and_then(|v| v.as_i64()),
                quota_bytes_in: parsed.get("bytes_in").and_then(|v| v.as_i64()),
                quota_bytes_out: parsed.get("bytes_out").and_then(|v| v.as_i64()),
            };
            match store.update_quota(id, &q).await {
                Ok(_) => {
                    info!("admin_quota_update id={id}");
                    Ok(json(StatusCode::OK, r#"{"updated":true}"#))
                }
                Err(e) => Ok(json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("{{\"error\":\"{e}\"}}"),
                )),
            }
        }
        (hyper::Method::POST, "passwd") => {
            let password = crate::user_store::generate_password();
            match store.set_password(id, &password).await {
                Ok(_) => {
                    info!("admin_user_passwd id={id}");
                    Ok(json(
                        StatusCode::OK,
                        &serde_json::json!({"password": password}).to_string(),
                    ))
                }
                Err(e) => Ok(json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("{{\"error\":\"{e}\"}}"),
                )),
            }
        }
        (hyper::Method::POST, "disable") => match store.set_status(id, "disabled").await {
            Ok(_) => {
                info!("admin_user_disable id={id}");
                Ok(json(StatusCode::OK, r#"{"status":"disabled"}"#))
            }
            Err(e) => Ok(json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("{{\"error\":\"{e}\"}}"),
            )),
        },
        (hyper::Method::POST, "enable") => match store.set_status(id, "active").await {
            Ok(_) => {
                info!("admin_user_enable id={id}");
                Ok(json(StatusCode::OK, r#"{"status":"active"}"#))
            }
            Err(e) => Ok(json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("{{\"error\":\"{e}\"}}"),
            )),
        },
        (hyper::Method::DELETE, "delete") => match store.delete_user(id).await {
            Ok(_) => {
                info!("admin_user_delete id={id}");
                if let Some(_u) = username {
                    rbac.set_role(&id.to_string(), "");
                }
                Ok(json(StatusCode::OK, r#"{"deleted":true}"#))
            }
            Err(e) => Ok(json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("{{\"error\":\"{e}\"}}"),
            )),
        },
        _ => Ok(json(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"method_not_allowed"}"#,
        )),
    }
}

// ─── Roles ──────────────────────────────────────────────

async fn handle_set_role(
    req: Request<Incoming>,
    rest: &str,
    store: &UserStore,
    rbac: &Rbac,
) -> Result<Response<String>, hyper::Error> {
    let id: uuid::Uuid = match rest.parse() {
        Ok(i) => i,
        Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_id"}"#)),
    };
    let body = read_body(req).await;
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_json"}"#)),
    };
    let role = parsed
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("user");
    match store.set_role(id, role).await {
        Ok(_) => {
            rbac.set_role(&id.to_string(), role);
            info!("admin_role_set id={id} role={role}");
            Ok(json(StatusCode::OK, r#"{"updated":true}"#))
        }
        Err(e) => Ok(json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{{\"error\":\"{e}\"}}"),
        )),
    }
}

// ─── Metrics ────────────────────────────────────────────

async fn handle_metrics(
    path: &str,
    store: &UserStore,
    claims: &Claims,
) -> Result<Response<String>, hyper::Error> {
    // GET /api/metrics/system — system-wide Prometheus metrics (JSON summary)
    if path == "/api/metrics/system" {
        let metrics_text = crate::metrics::render();
        // Extract key metrics into JSON
        let active_conn = extract_metric(&metrics_text, "ai_proxy_active_connections");
        let cert_cache = extract_metric(&metrics_text, "ai_proxy_cert_cache_entries");
        let vault = extract_metric(&metrics_text, "ai_proxy_vault_connected");
        let resp = serde_json::json!({
            "active_connections": active_conn,
            "cert_cache_entries": cert_cache,
            "vault_connected": vault,
            "prometheus_raw_lines": metrics_text.lines().count(),
        });
        return Ok(json(StatusCode::OK, &resp.to_string()));
    }

    // GET /api/metrics/users — all users usage (admin only, enforced by RBAC)
    if path == "/api/metrics/users" {
        let users = match store.list_users().await {
            Ok(u) => u,
            Err(e) => {
                return Ok(json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("{{\"error\":\"{e}\"}}"),
                ));
            }
        };
        let mut results = Vec::new();
        for u in &users {
            let usage = store.get_usage_total(u.id).await.unwrap_or_default();
            results.push(serde_json::json!({
                "username": u.username,
                "role": u.role,
                "status": u.status,
                "req": usage.req,
                "tok_in": usage.tok_in,
                "tok_out": usage.tok_out,
                "bytes_in": usage.bytes_in,
                "bytes_out": usage.bytes_out,
            }));
        }
        return Ok(json(
            StatusCode::OK,
            &serde_json::json!(results).to_string(),
        ));
    }

    // GET /api/metrics/self — own usage (user role)
    if path == "/api/metrics/self" {
        let uid: uuid::Uuid = claims.sub.parse().unwrap_or_default();
        let usage = store.get_usage_total(uid).await.unwrap_or_default();
        return Ok(json(
            StatusCode::OK,
            &serde_json::json!({
                "req": usage.req,
                "tok_in": usage.tok_in,
                "tok_out": usage.tok_out,
                "bytes_in": usage.bytes_in,
                "bytes_out": usage.bytes_out,
            })
            .to_string(),
        ));
    }

    // GET /api/metrics/users/{id} — specific user (admin only)
    if let Some(rest) = path.strip_prefix("/api/metrics/users/") {
        let id: uuid::Uuid = match rest.parse() {
            Ok(i) => i,
            Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_id"}"#)),
        };
        let row = match store.get_user_by_id(id).await {
            Ok(Some(r)) => r,
            _ => return Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#)),
        };
        let usage = store.get_usage_total(id).await.unwrap_or_default();
        return Ok(json(
            StatusCode::OK,
            &serde_json::json!({
                "username": row.username,
                "role": row.role,
                "req": usage.req,
                "tok_in": usage.tok_in,
                "tok_out": usage.tok_out,
                "bytes_in": usage.bytes_in,
                "bytes_out": usage.bytes_out,
            })
            .to_string(),
        ));
    }

    Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#))
}

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

// ─── Quota self ─────────────────────────────────────────

async fn handle_quota_self(
    store: &UserStore,
    claims: &Claims,
) -> Result<Response<String>, hyper::Error> {
    let uid: uuid::Uuid = match claims.sub.parse() {
        Ok(u) => u,
        Err(_) => return Ok(json(StatusCode::BAD_REQUEST, r#"{"error":"bad_token"}"#)),
    };
    let row = match store.get_user_by_id(uid).await {
        Ok(Some(r)) => r,
        _ => return Ok(json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#)),
    };
    let usage = store.get_usage(uid).await.unwrap_or_default();
    Ok(json(
        StatusCode::OK,
        &serde_json::json!({
            "username": row.username,
            "role": row.role,
            "quota": {
                "req_day": row.quota_req_day, "tok_in": row.quota_tok_in,
                "tok_out": row.quota_tok_out, "bytes_in": row.quota_bytes_in,
                "bytes_out": row.quota_bytes_out,
            },
            "usage_today": {
                "req": usage.req, "tok_in": usage.tok_in, "tok_out": usage.tok_out,
                "bytes_in": usage.bytes_in, "bytes_out": usage.bytes_out,
            }
        })
        .to_string(),
    ))
}

// ─── Helpers ────────────────────────────────────────────

fn json(status: StatusCode, body: &str) -> Response<String> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .body(body.to_string())
        .unwrap()
}

async fn read_body(req: Request<Incoming>) -> String {
    use http_body_util::BodyExt;
    match req.into_body().collect().await {
        Ok(bytes) => String::from_utf8_lossy(&bytes.to_bytes()).to_string(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── json helper ─────────────────────────────────────────

    #[test]
    fn test_json_response_ok() {
        let resp = json(StatusCode::OK, r#"{"status":"ok"}"#);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(resp.body(), r#"{"status":"ok"}"#);
    }

    #[test]
    fn test_json_response_unauthorized() {
        let resp = json(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_json_content_length_matches_body() {
        let body = r#"{"data":"hello"}"#;
        let resp = json(StatusCode::OK, body);
        let cl = resp
            .headers()
            .get("Content-Length")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cl, body.len().to_string());
    }

    // ─── extract_metric ──────────────────────────────────────

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
