use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

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
            AuthErrorCode::UserNotFound => 2000,
            AuthErrorCode::InvalidCredential => 2001,
            AuthErrorCode::UserLocked => 2002,
            AuthErrorCode::UserDisabled => 2003,
            AuthErrorCode::LoginExpired => 2004,
            AuthErrorCode::InvalidLoginState => 2005,
            AuthErrorCode::CredentialTypeUnsupported => 2006,
            AuthErrorCode::InvalidOtp => 2007,
            AuthErrorCode::TooManyAttempts => 2008,
            AuthErrorCode::SessionNotFound => 2009,
            AuthErrorCode::SessionExpired => 2010,
            AuthErrorCode::SessionRevoked => 2011,
            AuthErrorCode::IdentifierRequired => 2012,
        }
    }
}
