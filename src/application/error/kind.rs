use axum::http::StatusCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    Unauthorized,
    Forbidden,
    Conflict,
    Validation,
    RateLimit,
    Gone,
    Internal,
}

impl ErrorKind {
    pub fn http_status(self) -> StatusCode {
        match self {
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::Validation => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorKind::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            ErrorKind::Gone => StatusCode::GONE,
            ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
