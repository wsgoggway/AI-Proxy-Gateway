//! Typed application errors with axum IntoResponse.
//! Replaces the manual `json(StatusCode::..., r#"{"error":"..."}"#)` pattern.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("proxy error: {0}")]
    Proxy(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.as_str()),
            Self::Conflict(m) => (StatusCode::CONFLICT, m.as_str()),
            Self::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            Self::Proxy(m) => (StatusCode::BAD_GATEWAY, m.as_str()),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

impl From<hyper::Error> for AppError {
    fn from(e: hyper::Error) -> Self {
        Self::Proxy(e.to_string())
    }
}
