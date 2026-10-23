use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    /// Carries how many seconds until the caller may try again.
    #[error("too many requests")]
    TooMany(u64),
    #[error("internal error")]
    Internal(String),
}

pub type Res<T> = Result<T, AppError>;

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => AppError::NotFound("not found".into()),
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                AppError::Conflict("already exists".into())
            }
            _ => AppError::Internal(e.to_string()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::TooMany(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::Internal(detail) => {
                tracing::error!(%detail, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let retry_after = match &self {
            AppError::TooMany(secs) => Some(*secs),
            _ => None,
        };
        let mut response = (
            status,
            Json(json!({ "error": self.to_string(), "retry_after": retry_after })),
        )
            .into_response();
        if let Some(secs) = retry_after {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from(secs),
            );
        }
        response
    }
}
