use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 13000-13099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallErrorCode {
    AlreadyInitialized,
    UsernameRequired,
    EmailRequired,
    PasswordRequired,
    DomainRequired,
    DomainInvalid,
    EmailInvalid,
    UsernameExists,
    EmailExists,
    UnsupportedAlgorithm,
    ApplicationUrlInvalid,
}

impl AppErrorCode for InstallErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::AlreadyInitialized | Self::UsernameExists | Self::EmailExists => {
                ErrorKind::Conflict
            }
            Self::UsernameRequired
            | Self::EmailRequired
            | Self::PasswordRequired
            | Self::DomainRequired
            | Self::DomainInvalid
            | Self::EmailInvalid
            | Self::UnsupportedAlgorithm
            | Self::ApplicationUrlInvalid => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::AlreadyInitialized => 13000,
            Self::UsernameRequired => 13001,
            Self::EmailRequired => 13002,
            Self::PasswordRequired => 13003,
            Self::DomainRequired => 13004,
            Self::DomainInvalid => 13005,
            Self::EmailInvalid => 13006,
            Self::UsernameExists => 13007,
            Self::EmailExists => 13008,
            Self::UnsupportedAlgorithm => 13009,
            Self::ApplicationUrlInvalid => 13010,
        }
    }
}
