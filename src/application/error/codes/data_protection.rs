use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for data protection (encryption/decryption) operations.
/// Range: 9000–9099
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
            Self::InvalidProtectedPayload => 9000,
            Self::KeyRingEmpty => 9001,
            Self::EncryptionFailed => 9002,
        }
    }
}
