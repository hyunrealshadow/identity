use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for the RFC 8628 device authorization endpoint and the shared
/// verification interaction. Range: 26000-26099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthorizationErrorCode {
    // --- device authorization request ---
    /// `client_id` parameter is missing from the request.
    ClientIdRequired,
    /// Client registration does not permit the device code grant.
    GrantNotAllowed,
    /// `scope` parameter could not be parsed.
    ScopeInvalid,
    /// Requested scope is not assigned to the client.
    ScopeNotAssignedToClient,
    /// The user code space is exhausted for this moment.
    UserCodeUnavailable,
    /// Device code or user code generation failed.
    CodeGenerationFailed,
    /// Database write of the device authorization request failed.
    StoreRequestFailed,
    /// The provider issuer is missing or malformed.
    IssuerInvalid,

    // --- verification interaction ---
    /// The submitted user code is unknown, expired, or already decided.
    UserCodeNotFound,
    /// Database read of the device authorization request failed.
    LoadRequestFailed,
    /// Stored device authorization request could not be deserialized.
    DeserializeRequestFailed,
    /// The request is no longer pending, so the decision was discarded.
    RequestAlreadyDecided,
    /// The stored device authorization relation is missing or malformed.
    InvalidAuthorizationState,
    /// Database write of the user decision failed.
    StoreDecisionFailed,
    /// The user lookup for the approving account failed.
    UserLookupFailed,
    /// Database read of the client registration failed.
    ClientLookupFailed,
    /// The client registration no longer exists.
    ClientNotFound,
    /// The approving user was not found.
    UserNotFound,
    /// The request expired before the user decided.
    RequestExpired,
    /// The browser answering the verification has no active session.
    VerificationLoginRequired,
}

impl AppErrorCode for DeviceAuthorizationErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::ClientIdRequired => ErrorKind::Validation,
            Self::GrantNotAllowed => ErrorKind::Validation,
            Self::ScopeInvalid => ErrorKind::Validation,
            Self::ScopeNotAssignedToClient => ErrorKind::Validation,
            Self::UserCodeUnavailable => ErrorKind::Internal,
            Self::CodeGenerationFailed => ErrorKind::Internal,
            Self::StoreRequestFailed => ErrorKind::Internal,
            Self::IssuerInvalid => ErrorKind::Internal,
            Self::UserCodeNotFound => ErrorKind::Validation,
            Self::LoadRequestFailed => ErrorKind::Internal,
            Self::DeserializeRequestFailed => ErrorKind::Internal,
            Self::RequestAlreadyDecided => ErrorKind::Conflict,
            Self::InvalidAuthorizationState => ErrorKind::Internal,
            Self::StoreDecisionFailed => ErrorKind::Internal,
            Self::UserLookupFailed => ErrorKind::Internal,
            Self::ClientLookupFailed => ErrorKind::Internal,
            Self::ClientNotFound => ErrorKind::Validation,
            Self::UserNotFound => ErrorKind::Validation,
            Self::RequestExpired => ErrorKind::Gone,
            Self::VerificationLoginRequired => ErrorKind::Unauthorized,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::ClientIdRequired => 26000,
            Self::GrantNotAllowed => 26001,
            Self::ScopeInvalid => 26002,
            Self::ScopeNotAssignedToClient => 26003,
            Self::UserCodeUnavailable => 26005,
            Self::CodeGenerationFailed => 26006,
            Self::StoreRequestFailed => 26007,
            Self::IssuerInvalid => 26009,
            Self::UserCodeNotFound => 26010,
            Self::LoadRequestFailed => 26012,
            Self::DeserializeRequestFailed => 26013,
            Self::RequestAlreadyDecided => 26014,
            Self::InvalidAuthorizationState => 26015,
            Self::StoreDecisionFailed => 26016,
            Self::UserLookupFailed => 26017,
            Self::ClientLookupFailed => 26020,
            Self::ClientNotFound => 26021,
            Self::UserNotFound => 26018,
            Self::RequestExpired => 26019,
            Self::VerificationLoginRequired => 26022,
        }
    }
}
