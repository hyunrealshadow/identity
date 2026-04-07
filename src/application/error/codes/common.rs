use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonErrorCode {
    InvalidRequest,
    InternalError,
}

impl AppErrorCode for CommonErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidRequest => ErrorKind::Validation,
            Self::InternalError => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidRequest => 1000,
            Self::InternalError => 1001,
        }
    }
}
