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
    ResourceLookupFailed,
    PushedRequestStorageFailed,
}

impl AppErrorCode for CommonErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidRequest => ErrorKind::Validation,
            Self::InternalError => ErrorKind::Internal,
            Self::ValidationFailed => ErrorKind::Validation,
            Self::Unauthorized => ErrorKind::Unauthorized,
            Self::Forbidden => ErrorKind::Forbidden,
            Self::NotFound => ErrorKind::NotFound,
            Self::InvalidTarget => ErrorKind::Validation,
            Self::ResourceLookupFailed => ErrorKind::Internal,
            Self::PushedRequestStorageFailed => ErrorKind::Internal,
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
            Self::ResourceLookupFailed => 10007,
            Self::PushedRequestStorageFailed => 10008,
        }
    }
}
