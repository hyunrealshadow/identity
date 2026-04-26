use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 20000-20099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderErrorCode {
    NotInitialized,
    DomainMissing,
    IssuerMustUseHttps,
    IssuerMustNotHaveQueryOrFragment,
    IssuerUrlParseFailed,
}

impl AppErrorCode for ProviderErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::NotInitialized => ErrorKind::Validation,
            Self::DomainMissing => ErrorKind::Validation,
            Self::IssuerMustUseHttps => ErrorKind::Validation,
            Self::IssuerMustNotHaveQueryOrFragment => ErrorKind::Validation,
            Self::IssuerUrlParseFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::NotInitialized => 20000,
            Self::DomainMissing => 20001,
            Self::IssuerMustUseHttps => 20002,
            Self::IssuerMustNotHaveQueryOrFragment => 20003,
            Self::IssuerUrlParseFailed => 20004,
        }
    }
}
