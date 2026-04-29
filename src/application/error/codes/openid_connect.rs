use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for OIDC userinfo and token validation.
/// Range: 21000-21099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenIdConnectErrorCode {
    InvalidToken,
    InsufficientScope,
    UserNotFound,
}

impl AppErrorCode for OpenIdConnectErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidToken => ErrorKind::Unauthorized,
            Self::InsufficientScope => ErrorKind::Forbidden,
            Self::UserNotFound => ErrorKind::NotFound,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidToken => 21000,
            Self::InsufficientScope => 21001,
            Self::UserNotFound => 21002,
        }
    }
}
