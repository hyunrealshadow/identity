use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for data protection (encryption/decryption) operations.
/// Range: 14000-14099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataProtectionErrorCode {
    InvalidProtectedPayload,
    KeyRingEmpty,
    EncryptionFailed,
}

impl AppErrorCode for DataProtectionErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::InvalidProtectedPayload => ErrorKind::Validation,
            Self::KeyRingEmpty => ErrorKind::Internal,
            Self::EncryptionFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::InvalidProtectedPayload => 14000,
            Self::KeyRingEmpty => 14001,
            Self::EncryptionFailed => 14002,
        }
    }
}
