use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 25000-25099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationErrorCode {
    DynamicRegistrationDisabled,
    RedirectUrisRequired,
    UnsupportedApplicationType,
    UnsupportedSubjectType,
    ClientCreateFailed,
    InvalidRegistrationAccessToken,
    ClientLookupFailed,
    NoneNotSupported,
    InvalidRedirectUri,
    InvalidClientMetadata,
    ClientDeleteFailed,
    BuiltInClientCannotBeDeleted,
    ClientUpdateFailed,
    ClientUpdateForbidden,
}

impl AppErrorCode for RegistrationErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::DynamicRegistrationDisabled
            | Self::RedirectUrisRequired
            | Self::UnsupportedApplicationType
            | Self::UnsupportedSubjectType
            | Self::NoneNotSupported
            | Self::InvalidRedirectUri
            | Self::InvalidClientMetadata
            | Self::BuiltInClientCannotBeDeleted => ErrorKind::Validation,

            Self::ClientCreateFailed
            | Self::ClientUpdateFailed
            | Self::ClientLookupFailed
            | Self::ClientDeleteFailed => ErrorKind::Internal,

            Self::ClientUpdateForbidden => ErrorKind::Forbidden,
            Self::InvalidRegistrationAccessToken => ErrorKind::Unauthorized,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::DynamicRegistrationDisabled => 25000,
            Self::RedirectUrisRequired => 25001,
            Self::UnsupportedApplicationType => 25002,
            Self::UnsupportedSubjectType => 25003,
            Self::ClientCreateFailed => 25004,
            Self::ClientUpdateFailed => 25012,
            Self::ClientUpdateForbidden => 25013,
            Self::InvalidRegistrationAccessToken => 25005,
            Self::ClientLookupFailed => 25006,
            Self::NoneNotSupported => 25007,
            Self::InvalidRedirectUri => 25008,
            Self::InvalidClientMetadata => 25009,
            Self::ClientDeleteFailed => 25010,
            Self::BuiltInClientCannotBeDeleted => 25011,
        }
    }
}
