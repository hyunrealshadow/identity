use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 10000-10099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonErrorCode {
    InvalidRequest,
    InternalError,
    ValidationFailed,
    Unauthorized,
    Forbidden,
    NotFound,
    InvalidTarget,
    InvalidScope,
    ResourceLookupFailed,
    PushedRequestStorageFailed,
}

impl AppErrorCode for CommonErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidRequest
            | Self::ValidationFailed
            | Self::InvalidTarget
            | Self::InvalidScope => ErrorKind::Validation,
            Self::InternalError | Self::ResourceLookupFailed | Self::PushedRequestStorageFailed => {
                ErrorKind::Internal
            }

            Self::Unauthorized => ErrorKind::Unauthorized,
            Self::Forbidden => ErrorKind::Forbidden,
            Self::NotFound => ErrorKind::NotFound,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidRequest => 10000,
            Self::InternalError => 10001,
            Self::ValidationFailed => 10002,
            Self::Unauthorized => 10003,
            Self::Forbidden => 10004,
            Self::NotFound => 10005,
            Self::InvalidTarget => 10006,
            Self::InvalidScope => 10009,
            Self::ResourceLookupFailed => 10007,
            Self::PushedRequestStorageFailed => 10008,
        }
    }
}
