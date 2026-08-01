use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 15000-15099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountErrorCode {
    ValidationFailed,
    UsernameRequired,
    UsernameInvalid,
    EmailRequired,
    EmailInvalid,
    UsernameExists,
    EmailExists,
}

impl AppErrorCode for AccountErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::ValidationFailed
            | Self::UsernameRequired
            | Self::UsernameInvalid
            | Self::EmailRequired
            | Self::EmailInvalid => ErrorKind::Validation,
            Self::UsernameExists | Self::EmailExists => ErrorKind::Conflict,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::ValidationFailed => 15000,
            Self::UsernameRequired => 15001,
            Self::UsernameInvalid => 15002,
            Self::EmailRequired => 15003,
            Self::EmailInvalid => 15004,
            Self::UsernameExists => 15005,
            Self::EmailExists => 15006,
        }
    }
}
