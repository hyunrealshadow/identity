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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::Validation => "validation",
            Self::RateLimit => "rate_limit",
            Self::Gone => "gone",
            Self::Internal => "internal",
        }
    }
}
