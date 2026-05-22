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
}

impl AppErrorCode for RegistrationErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::DynamicRegistrationDisabled => ErrorKind::Validation,
            Self::RedirectUrisRequired => ErrorKind::Validation,
            Self::UnsupportedApplicationType => ErrorKind::Validation,
            Self::UnsupportedSubjectType => ErrorKind::Validation,
            Self::ClientCreateFailed => ErrorKind::Internal,
            Self::InvalidRegistrationAccessToken => ErrorKind::Unauthorized,
            Self::ClientLookupFailed => ErrorKind::Internal,
            Self::NoneNotSupported => ErrorKind::Validation,
            Self::InvalidRedirectUri => ErrorKind::Validation,
            Self::InvalidClientMetadata => ErrorKind::Validation,
            Self::ClientDeleteFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::DynamicRegistrationDisabled => 25000,
            Self::RedirectUrisRequired => 25001,
            Self::UnsupportedApplicationType => 25002,
            Self::UnsupportedSubjectType => 25003,
            Self::ClientCreateFailed => 25004,
            Self::InvalidRegistrationAccessToken => 25005,
            Self::ClientLookupFailed => 25006,
            Self::NoneNotSupported => 25007,
            Self::InvalidRedirectUri => 25008,
            Self::InvalidClientMetadata => 25009,
            Self::ClientDeleteFailed => 25010,
        }
    }
}
