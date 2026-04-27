use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    application::error::{AppError, codes::key::KeyErrorCode},
    domain::key::{
        CreateKeyJwkInput, KeyJwkRepository,
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
        model::{AsymmetricKeyAlgorithm, Key, KeyData, KeyType},
        repository::KeyRepository,
    },
    infrastructure::crypto::key::generate_all_jwks_for_key,
};

#[derive(Debug, Clone)]
pub struct GenerateAsymmetricKeyInput {
    pub algorithm: AsymmetricKeyAlgorithm,
    pub expires_at: Option<DateTime<Utc>>,
    pub certificate: Option<String>,
}

pub struct AsymmetricKeyService {
    pub(crate) repo: Arc<dyn KeyRepository>,
    pub(crate) generator: Arc<dyn AsymmetricKeyGenerator>,
    pub(crate) jwk_repo: Option<Arc<dyn KeyJwkRepository>>,
}

impl AsymmetricKeyService {
    pub async fn list_available(&self) -> Result<Vec<Key>, AppError> {
        Ok(self.repo.list_available_asymmetric().await?)
    }

    pub async fn list_available_jwks(&self) -> Result<Vec<crate::domain::key::KeyJwk>, AppError> {
        match self.jwk_repo {
            Some(ref jwk_repo) => Ok(jwk_repo.list_active().await?),
            None => Ok(vec![]),
        }
    }

    pub async fn generate_and_store(
        &self,
        input: GenerateAsymmetricKeyInput,
    ) -> Result<Key, AppError> {
        input
            .algorithm
            .validate()
            .map_err(|_| AppError::from_code(KeyErrorCode::AlgorithmInvalid))?;

        let spec = AsymmetricKeySpec {
            algorithm: input.algorithm,
        };

        let mut data = self.generator.generate(&spec)?;

        if let Some(certificate) = input.certificate {
            validate_certificate_pem(&certificate)?;
            data.certificate = Some(certificate);
        }

        let key = self
            .repo
            .create(
                KeyType::Asymmetric,
                &KeyData::Asymmetric(data.clone()),
                input.expires_at,
            )
            .await?;

        if let Some(ref jwk_repo) = self.jwk_repo {
            jwk_repo.create_batch(build_jwk_inputs(&key)?).await?;
        }

        Ok(key)
    }

    pub async fn get_by_oid(&self, oid: Uuid) -> Result<Key, AppError> {
        let key = self
            .repo
            .find_by_oid(oid.into())
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))?;

        if key.revoked_at.is_some() {
            return Err(AppError::from_code(KeyErrorCode::Revoked));
        }

        if let Some(ref jwk_repo) = self.jwk_repo {
            jwk_repo.delete_by_key_oid(key.oid).await?;
            jwk_repo.create_batch(build_jwk_inputs(&key)?).await?;
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
            .update_certificate_by_oid(oid.into(), certificate_pem)
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))?;

        if key.revoked_at.is_some() {
            return Err(AppError::from_code(KeyErrorCode::Revoked));
        }

        Ok(key)
    }

    pub async fn revoke(&self, oid: Uuid) -> Result<Key, AppError> {
        self.repo
            .revoke_by_oid(oid.into(), Utc::now())
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))
    }
}

fn build_jwk_inputs(key: &Key) -> Result<Vec<CreateKeyJwkInput>, AppError> {
    let KeyData::Asymmetric(data) = &key.data else {
        return Ok(vec![]);
    };

    let key_id = Uuid::from(key.oid).to_string();
    let jwks = generate_all_jwks_for_key(&data.private_key, &key_id, data.certificate.as_deref())
        .map_err(|error| {
        AppError::from_code(KeyErrorCode::JwkGenerationFailed).with_source(error)
    })?;

    jwks.into_iter()
        .map(|(algorithm, jwk)| {
            let jwk = serde_json::to_value(jwk).map_err(|error| {
                AppError::from_code(KeyErrorCode::JwkSerializationFailed).with_source(error)
            })?;

            Ok(CreateKeyJwkInput {
                key_oid: key.oid,
                algorithm,
                jwk,
            })
        })
        .collect()
}

fn validate_certificate_pem(certificate_pem: &str) -> Result<(), AppError> {
    let trimmed = certificate_pem.trim();
    if trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        && trimmed.ends_with("-----END CERTIFICATE-----")
    {
        return Ok(());
    }

    Err(AppError::from_code(KeyErrorCode::InvalidCertificatePem))
}
