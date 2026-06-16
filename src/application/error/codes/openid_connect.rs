use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for OIDC userinfo and token validation.
/// Range: 21000-21099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenIdConnectErrorCode {
    InvalidToken,
    InsufficientScope,
    UserNotFound,
    PostLogoutRedirectUriNotRegistered,
    IdTokenHintIssuerInvalid,
    PostLogoutRedirectUriInvalid,
    LogoutClientRequired,
    LogoutClientInvalid,
    LogoutClientLookupFailed,
    LogoutClientNotFound,
    IdTokenHintInvalid,
    IdTokenHintRequired,
    /// The `Authorization` header does not use the Bearer scheme (RFC 6750).
    BearerSchemeInvalid,
    /// The `Authorization` header is missing (RFC 6750).
    AuthorizationHeaderRequired,
    /// No Bearer token in the `Authorization` header or `access_token` body parameter.
    AccessTokenRequired,
}

impl AppErrorCode for OpenIdConnectErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidToken => ErrorKind::Unauthorized,
            Self::InsufficientScope => ErrorKind::Forbidden,
            Self::UserNotFound => ErrorKind::NotFound,
            Self::BearerSchemeInvalid
            | Self::AuthorizationHeaderRequired
            | Self::AccessTokenRequired
            | Self::PostLogoutRedirectUriNotRegistered
            | Self::IdTokenHintIssuerInvalid
            | Self::PostLogoutRedirectUriInvalid
            | Self::LogoutClientRequired
            | Self::LogoutClientInvalid
            | Self::LogoutClientNotFound
            | Self::IdTokenHintInvalid
            | Self::IdTokenHintRequired => ErrorKind::Validation,
            Self::LogoutClientLookupFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidToken => 21000,
            Self::InsufficientScope => 21001,
            Self::UserNotFound => 21002,
            Self::PostLogoutRedirectUriNotRegistered => 21003,
            Self::IdTokenHintIssuerInvalid => 21004,
            Self::PostLogoutRedirectUriInvalid => 21005,
            Self::LogoutClientRequired => 21006,
            Self::LogoutClientInvalid => 21007,
            Self::LogoutClientLookupFailed => 21008,
            Self::LogoutClientNotFound => 21009,
            Self::IdTokenHintInvalid => 21010,
            Self::IdTokenHintRequired => 21011,
            Self::BearerSchemeInvalid => 21012,
            Self::AuthorizationHeaderRequired => 21013,
            Self::AccessTokenRequired => 21014,
        }
    }
}
