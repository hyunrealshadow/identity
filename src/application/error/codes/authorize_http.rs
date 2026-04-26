use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for the `/oauth2/authorize` HTTP layer:
/// request extraction, method validation, and interaction routing.
/// Range: 22000-22099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeHttpErrorCode {
    /// POST request does not use `application/x-www-form-urlencoded` Content-Type.
    PostContentTypeInvalid,
    /// HTTP method is neither GET nor POST.
    MethodNotAllowed,
    /// One or more required OAuth parameters are missing.
    RequiredParamMissing,
    /// Internal client reached the authorize endpoint without an active session.
    InternalClientLoginRequired,
    /// Consent request references an account with no matching active session.
    ConsentSessionNotFound,
}

impl AppErrorCode for AuthorizeHttpErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::PostContentTypeInvalid => ErrorKind::Validation,
            Self::MethodNotAllowed => ErrorKind::Validation,
            Self::RequiredParamMissing => ErrorKind::Validation,
            Self::InternalClientLoginRequired => ErrorKind::Validation,
            Self::ConsentSessionNotFound => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::PostContentTypeInvalid => 22000,
            Self::MethodNotAllowed => 22001,
            Self::RequiredParamMissing => 22002,
            Self::InternalClientLoginRequired => 22003,
            Self::ConsentSessionNotFound => 22004,
        }
    }
}
