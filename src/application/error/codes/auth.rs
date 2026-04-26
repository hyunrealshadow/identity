use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 11000-11099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthErrorCode {
    UserNotFound,
    InvalidCredential,
    UserLocked,
    UserDisabled,
    LoginExpired,
    InvalidLoginState,
    CredentialTypeUnsupported,
    InvalidOtp,
    TooManyAttempts,
    SessionNotFound,
    SessionExpired,
    SessionRevoked,
    IdentifierRequired,
}

impl AppErrorCode for AuthErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            AuthErrorCode::UserNotFound => ErrorKind::NotFound,
            AuthErrorCode::InvalidCredential => ErrorKind::Unauthorized,
            AuthErrorCode::UserLocked => ErrorKind::Forbidden,
            AuthErrorCode::UserDisabled => ErrorKind::Forbidden,
            AuthErrorCode::LoginExpired => ErrorKind::Gone,
            AuthErrorCode::InvalidLoginState => ErrorKind::Conflict,
            AuthErrorCode::CredentialTypeUnsupported => ErrorKind::Validation,
            AuthErrorCode::InvalidOtp => ErrorKind::Unauthorized,
            AuthErrorCode::TooManyAttempts => ErrorKind::RateLimit,
            AuthErrorCode::SessionNotFound => ErrorKind::NotFound,
            AuthErrorCode::SessionExpired => ErrorKind::Unauthorized,
            AuthErrorCode::SessionRevoked => ErrorKind::Unauthorized,
            AuthErrorCode::IdentifierRequired => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            AuthErrorCode::UserNotFound => 11000,
            AuthErrorCode::InvalidCredential => 11001,
            AuthErrorCode::UserLocked => 11002,
            AuthErrorCode::UserDisabled => 11003,
            AuthErrorCode::LoginExpired => 11004,
            AuthErrorCode::InvalidLoginState => 11005,
            AuthErrorCode::CredentialTypeUnsupported => 11006,
            AuthErrorCode::InvalidOtp => 11007,
            AuthErrorCode::TooManyAttempts => 11008,
            AuthErrorCode::SessionNotFound => 11009,
            AuthErrorCode::SessionExpired => 11010,
            AuthErrorCode::SessionRevoked => 11011,
            AuthErrorCode::IdentifierRequired => 11012,
        }
    }
}
