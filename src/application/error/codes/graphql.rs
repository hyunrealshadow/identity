use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Stable GraphQL execution and schema errors. Range: 28000-28099.
///
/// These codes describe failures that happen before or around a resolver
/// result: guards, input validators, Global ID / cursor decoding, pagination
/// checks and internal adapter failures. They are deliberately separate from
/// the transport envelope codes (`GraphqlTransportErrorCode`, 28100-28199).
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
pub enum GraphqlErrorCode {
    ValidationFailed,
    InvalidCursor,
    PageSizeInvalid,
    InvalidGlobalId,
    UnsupportedNodeType,
    InsufficientScope,
    UserAuthenticationRequired,
    Forbidden,
    RecentAuthenticationRequired,
    BrowserSessionRequired,
    InvalidTheme,
    Internal,
    AuthenticationContextUnavailable,
    InvalidSessionId,
    PageArgumentsConflict,
    InstanceMetadataUnavailable,
    InvalidPasskeyChallenge,
    InvalidPasskeyId,
    SerializationFailed,
    AccountUnavailable,
}

impl GraphqlErrorCode {
    /// Every stable code in this module, from lowest to highest.
    pub const ALL: [Self; 20] = [
        Self::ValidationFailed,
        Self::InvalidCursor,
        Self::PageSizeInvalid,
        Self::InvalidGlobalId,
        Self::UnsupportedNodeType,
        Self::InsufficientScope,
        Self::UserAuthenticationRequired,
        Self::Forbidden,
        Self::RecentAuthenticationRequired,
        Self::BrowserSessionRequired,
        Self::InvalidTheme,
        Self::Internal,
        Self::AuthenticationContextUnavailable,
        Self::InvalidSessionId,
        Self::PageArgumentsConflict,
        Self::InstanceMetadataUnavailable,
        Self::InvalidPasskeyChallenge,
        Self::InvalidPasskeyId,
        Self::SerializationFailed,
        Self::AccountUnavailable,
    ];
}

impl AppErrorCode for GraphqlErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InsufficientScope
            | Self::Forbidden
            | Self::RecentAuthenticationRequired
            | Self::BrowserSessionRequired => ErrorKind::Forbidden,
            Self::UserAuthenticationRequired | Self::AuthenticationContextUnavailable => {
                ErrorKind::Unauthorized
            }
            Self::Internal | Self::InstanceMetadataUnavailable | Self::SerializationFailed => {
                ErrorKind::Internal
            }
            Self::AccountUnavailable => ErrorKind::NotFound,
            Self::ValidationFailed
            | Self::InvalidCursor
            | Self::PageSizeInvalid
            | Self::InvalidGlobalId
            | Self::UnsupportedNodeType
            | Self::InvalidTheme
            | Self::InvalidSessionId
            | Self::PageArgumentsConflict
            | Self::InvalidPasskeyChallenge
            | Self::InvalidPasskeyId => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::ValidationFailed => 28000,
            Self::InvalidCursor => 28001,
            Self::PageSizeInvalid => 28002,
            Self::InvalidGlobalId => 28003,
            Self::UnsupportedNodeType => 28004,
            Self::InsufficientScope => 28005,
            Self::UserAuthenticationRequired => 28006,
            Self::Forbidden => 28007,
            Self::RecentAuthenticationRequired => 28008,
            Self::BrowserSessionRequired => 28009,
            Self::InvalidTheme => 28010,
            Self::Internal => 28011,
            Self::AuthenticationContextUnavailable => 28012,
            Self::InvalidSessionId => 28013,
            Self::PageArgumentsConflict => 28014,
            Self::InstanceMetadataUnavailable => 28015,
            Self::InvalidPasskeyChallenge => 28016,
            Self::InvalidPasskeyId => 28017,
            Self::SerializationFailed => 28018,
            Self::AccountUnavailable => 28019,
        }
    }
}
