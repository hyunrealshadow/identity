use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyErrorCode {
    NotFound,
    Revoked,
}

impl AppErrorCode for KeyErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::NotFound => ErrorKind::NotFound,
            Self::Revoked => ErrorKind::Unauthorized,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::NotFound => 3000,
            Self::Revoked => 3001,
        }
    }
}
