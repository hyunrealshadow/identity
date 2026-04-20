use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyErrorCode {
    NotFound,
    Revoked,
    AlgorithmInvalid,
    InvalidCertificatePem,
    InvalidKeyType,
    CertificateRequiresAsymmetricKey,
}

impl AppErrorCode for KeyErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::NotFound => ErrorKind::NotFound,
            Self::Revoked => ErrorKind::Unauthorized,
            Self::AlgorithmInvalid => ErrorKind::Validation,
            Self::InvalidCertificatePem => ErrorKind::Validation,
            Self::InvalidKeyType => ErrorKind::Validation,
            Self::CertificateRequiresAsymmetricKey => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::NotFound => 3000,
            Self::Revoked => 3001,
            Self::AlgorithmInvalid => 3002,
            Self::InvalidCertificatePem => 3003,
            Self::InvalidKeyType => 3004,
            Self::CertificateRequiresAsymmetricKey => 3005,
        }
    }
}
