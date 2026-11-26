use crate::{
    application::error::{
        AppError,
        codes::{common, key},
    },
    domain::key::{
        generator::KeyMaterialError, jwk::KeyJwkRepositoryError, repository::KeyRepositoryError,
    },
};

impl From<KeyMaterialError> for AppError {
    fn from(error: KeyMaterialError) -> Self {
        match error {
            KeyMaterialError::InvalidInput(_) => {
                key::error::UnsupportedAlgorithm::new("unknown").into()
            }
            other => common::error::InternalError.with_source(other),
        }
    }
}

impl From<KeyRepositoryError> for AppError {
    fn from(error: KeyRepositoryError) -> Self {
        match error {
            KeyRepositoryError::InvalidKeyType(_) => key::error::InvalidKeyType.into(),
            KeyRepositoryError::CertificateRequiresAsymmetricKey => {
                key::error::CertificateRequiresAsymmetricKey.into()
            }
            other => common::error::InternalError.with_source(other),
        }
    }
}

impl From<KeyJwkRepositoryError> for AppError {
    fn from(error: KeyJwkRepositoryError) -> Self {
        common::error::InternalError.with_source(error)
    }
}
