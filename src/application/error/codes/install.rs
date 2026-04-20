use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

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
            Self::AlreadyInitialized => 8000,
            Self::UsernameRequired => 8001,
            Self::EmailRequired => 8002,
            Self::PasswordRequired => 8003,
            Self::DomainRequired => 8004,
            Self::DomainInvalid => 8005,
            Self::EmailInvalid => 8006,
            Self::UsernameExists => 8007,
            Self::EmailExists => 8008,
            Self::AlgorithmInvalid => 8009,
        }
    }
}
