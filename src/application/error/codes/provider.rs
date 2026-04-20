use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

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
            Self::NotInitialized => 8100,
            Self::DomainMissing => 8101,
            Self::IssuerMustUseHttps => 8102,
            Self::IssuerMustNotHaveQueryOrFragment => 8103,
            Self::IssuerUrlParseFailed => 8104,
        }
    }
}
