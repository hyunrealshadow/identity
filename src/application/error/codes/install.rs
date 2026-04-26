use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

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
    AlgorithmInvalid,
}

impl AppErrorCode for InstallErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::AlreadyInitialized => ErrorKind::Conflict,
            Self::UsernameRequired => ErrorKind::Validation,
            Self::EmailRequired => ErrorKind::Validation,
            Self::PasswordRequired => ErrorKind::Validation,
            Self::DomainRequired => ErrorKind::Validation,
            Self::DomainInvalid => ErrorKind::Validation,
            Self::EmailInvalid => ErrorKind::Validation,
            Self::UsernameExists => ErrorKind::Conflict,
            Self::EmailExists => ErrorKind::Conflict,
            Self::AlgorithmInvalid => ErrorKind::Validation,
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
            Self::AlgorithmInvalid => 13009,
        }
    }
}
