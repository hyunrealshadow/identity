use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Range: 12000-12099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyErrorCode {
    NotFound,
    Revoked,
    AlgorithmInvalid,
    InvalidCertificatePem,
    InvalidKeyType,
    CertificateRequiresAsymmetricKey,
    JwkGenerationFailed,
    JwkSerializationFailed,
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
            Self::JwkGenerationFailed => ErrorKind::Internal,
            Self::JwkSerializationFailed => ErrorKind::Internal,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::NotFound => 12000,
            Self::Revoked => 12001,
            Self::AlgorithmInvalid => 12002,
            Self::InvalidCertificatePem => 12003,
            Self::InvalidKeyType => 12004,
            Self::CertificateRequiresAsymmetricKey => 12005,
            Self::JwkGenerationFailed => 12006,
            Self::JwkSerializationFailed => 12007,
        }
    }
}
