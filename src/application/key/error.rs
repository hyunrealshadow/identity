use crate::{
    application::error::{
        AppError,
        codes::{common::CommonErrorCode, key::KeyErrorCode},
    },
    domain::key::{generator::KeyMaterialError, repository::KeyRepositoryError},
};

impl From<KeyMaterialError> for AppError {
    fn from(error: KeyMaterialError) -> Self {
        match error {
            KeyMaterialError::InvalidInput(_) => {
                AppError::from_code(KeyErrorCode::AlgorithmInvalid)
            }
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}

impl From<KeyRepositoryError> for AppError {
    fn from(error: KeyRepositoryError) -> Self {
        match error {
            KeyRepositoryError::InvalidKeyType(_) => {
                AppError::from_code(KeyErrorCode::InvalidKeyType)
            }
            KeyRepositoryError::CertificateRequiresAsymmetricKey => {
                AppError::from_code(KeyErrorCode::CertificateRequiresAsymmetricKey)
            }
            other => AppError::from_code(CommonErrorCode::InternalError).with_source(other),
        }
    }
}
