//! Axum extractors and middleware: JWT authentication + RBAC authorization.

use axum::extract::State;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::AppError;
use crate::state::AppState;

/// Middleware: extract JWT, verify, enforce RBAC, then inject Claims as extension.
/// Applied to all protected admin routes via `from_fn_with_state`.
/// Handlers that need claims use `Extension<Claims>`.
pub async fn auth_and_rbac(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract Bearer token
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .ok_or(AppError::Unauthorized)?;

    // Verify JWT
    let tokens = state
        .tokens
        .as_ref()
        .ok_or(AppError::Internal(anyhow::anyhow!("token manager not configured")))?;
    let claims = tokens
        .verify(&token)
        .map_err(|_| AppError::Unauthorized)?;

    // Enforce RBAC
    let path = req.uri().path().to_string();
    let method = match req.method().as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        _ => "OTHER",
    };

    if let Some(rbac) = &state.rbac {
        if !rbac.enforce(&claims.sub, &path, method) {
            return Err(AppError::Forbidden);
        }
    }

    // Inject claims for handlers that need them
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
