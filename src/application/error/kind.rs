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
