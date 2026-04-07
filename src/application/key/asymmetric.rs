use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    application::error::{
        AppError,
        codes::{common::CommonErrorCode, key::KeyErrorCode},
    },
    domain::key::{
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
        model::{AsymmetricKeyAlgorithm, Key, KeyData, KeyType},
        repository::KeyRepository,
    },
};

#[derive(Debug, Clone)]
pub struct GenerateAsymmetricKeyInput {
    pub algorithm: AsymmetricKeyAlgorithm,
    pub expires_at: Option<DateTime<Utc>>,
    pub certificate: Option<String>,
}

pub struct AsymmetricKeyService {
    pub repo: Arc<dyn KeyRepository>,
    pub generator: Arc<dyn AsymmetricKeyGenerator>,
}

impl AsymmetricKeyService {
    pub async fn list_available(&self) -> Result<Vec<Key>, AppError> {
        Ok(self.repo.list_available_asymmetric().await?)
    }

    pub async fn generate_and_store(
        &self,
        input: GenerateAsymmetricKeyInput,
    ) -> Result<Key, AppError> {
        input
            .algorithm
            .validate()
            .map_err(|_| AppError::from_code(CommonErrorCode::InvalidRequest))?;

        let spec = AsymmetricKeySpec {
            algorithm: input.algorithm,
        };

        let mut data = self.generator.generate(&spec)?;

        if let Some(certificate) = input.certificate {
            validate_certificate_pem(&certificate)?;
            data.certificate = Some(certificate);
        }

        Ok(self
            .repo
            .create(
                KeyType::Asymmetric,
                &KeyData::Asymmetric(data),
                input.expires_at,
            )
            .await?)
    }

    pub async fn get_by_oid(&self, oid: Uuid) -> Result<Key, AppError> {
        let key = self
            .repo
            .find_by_oid(oid)
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))?;

        if key.revoked_at.is_some() {
            return Err(AppError::from_code(KeyErrorCode::Revoked));
        }

        Ok(key)
    }

    pub async fn attach_certificate(
        &self,
        oid: Uuid,
        certificate_pem: &str,
    ) -> Result<Key, AppError> {
        validate_certificate_pem(certificate_pem)?;

        let key = self
            .repo
            .update_certificate_by_oid(oid, certificate_pem)
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))?;

        if key.revoked_at.is_some() {
            return Err(AppError::from_code(KeyErrorCode::Revoked));
        }

        Ok(key)
    }

    pub async fn revoke(&self, oid: Uuid) -> Result<Key, AppError> {
        self.repo
            .revoke_by_oid(oid, Utc::now())
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))
    }
}

fn validate_certificate_pem(certificate_pem: &str) -> Result<(), AppError> {
    let trimmed = certificate_pem.trim();
    if trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        && trimmed.ends_with("-----END CERTIFICATE-----")
    {
        return Ok(());
    }

    Err(AppError::from_code(CommonErrorCode::InvalidRequest))
}
