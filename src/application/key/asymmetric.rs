use std::sync::Arc;

use chrono::Utc;
use identity_domain::key::KeyJwk;
use uuid::Uuid;

use super::rotation::KEY_LIFETIME;
use crate::{
    application::error::{AppError, codes::key::KeyErrorCode},
    domain::key::{
        CreateKeyJwkInput, JwkAlgorithm, KeyJwkRepository, PublicJwk,
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
        model::{AsymmetricKeyAlgorithm, Key, KeyData},
        repository::KeyRepository,
    },
    key::runtime::RuntimeKeyRingProvider,
};

#[derive(Debug, Clone)]
pub struct GeneratedKeyJwk {
    pub algorithm: JwkAlgorithm,
    pub jwk: PublicJwk,
}

pub trait KeyJwkGenerator: Send + Sync {
    fn generate(
        &self,
        private_key_pem: &str,
        key_id: &str,
        certificate_pem: Option<&str>,
    ) -> Result<Vec<GeneratedKeyJwk>, AppError>;
}

#[derive(Debug, Clone)]
pub struct GenerateAsymmetricKeyInput {
    pub algorithm: AsymmetricKeyAlgorithm,
    pub certificate: Option<String>,
}

pub struct AsymmetricKeyService {
    repo: Arc<dyn KeyRepository>,
    generator: Arc<dyn AsymmetricKeyGenerator>,
    jwk_generator: Arc<dyn KeyJwkGenerator>,
    jwk_repo: Option<Arc<dyn KeyJwkRepository>>,
    runtime_key_ring: Option<Arc<dyn RuntimeKeyRingProvider>>,
}

impl AsymmetricKeyService {
    #[must_use]
    pub fn new(
        repo: Arc<dyn KeyRepository>,
        generator: Arc<dyn AsymmetricKeyGenerator>,
        jwk_generator: Arc<dyn KeyJwkGenerator>,
        jwk_repo: Option<Arc<dyn KeyJwkRepository>>,
    ) -> Self {
        Self {
            repo,
            generator,
            jwk_generator,
            jwk_repo,
            runtime_key_ring: None,
        }
    }

    #[must_use]
    pub fn with_runtime_key_ring(
        mut self,
        runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
    ) -> Self {
        self.runtime_key_ring = Some(runtime_key_ring);
        self
    }

    async fn refresh_runtime_key_ring(&self) -> Result<(), AppError> {
        if let Some(provider) = &self.runtime_key_ring {
            provider.refresh_value().await?;
        }
        Ok(())
    }

    pub async fn list_available(&self) -> Result<Vec<Key>, AppError> {
        Ok(self.repo.list_active_asymmetric().await?)
    }

    pub async fn list_available_jwks(&self) -> Result<Vec<KeyJwk>, AppError> {
        match self.jwk_repo {
            Some(ref jwk_repo) => {
                let mut jwks = jwk_repo.list_active().await?;
                if let Some(key_id) = self.runtime_key_ring.as_ref().and_then(|provider| {
                    provider
                        .current_value()
                        .signing_key()
                        .map(|key| key.key_id.clone())
                }) {
                    prioritize_current_signing_key(&mut jwks, &key_id);
                }
                Ok(jwks)
            }
            None => Ok(vec![]),
        }
    }

    pub async fn generate_and_store(
        &self,
        input: GenerateAsymmetricKeyInput,
    ) -> Result<Key, AppError> {
        input.algorithm.validate().map_err(|_| {
            AppError::from_code(KeyErrorCode::UnsupportedAlgorithm)
                .with_param("algorithm", input.algorithm.to_string())
        })?;

        let spec = AsymmetricKeySpec {
            algorithm: input.algorithm,
        };

        let mut data = self.generator.generate(&spec)?;

        if let Some(certificate) = input.certificate {
            validate_certificate_pem(&certificate)?;
            data.certificate = Some(certificate);
        }

        let expires_at = Some(Utc::now() + KEY_LIFETIME);
        let key = self
            .repo
            .create(&KeyData::Asymmetric(data.clone()), expires_at)
            .await?;

        if let Some(ref jwk_repo) = self.jwk_repo {
            jwk_repo
                .create_batch(build_jwk_inputs(&key, self.jwk_generator.as_ref())?)
                .await?;
        }

        self.refresh_runtime_key_ring().await?;
        Ok(key)
    }

    pub async fn get_by_oid(&self, oid: Uuid) -> Result<Key, AppError> {
        let key = self
            .repo
            .find_by_oid(oid.into())
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))?;

        if key.revoked_at.is_some()
            || key
                .expires_at
                .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return Err(AppError::from_code(KeyErrorCode::Revoked));
        }

        if let Some(ref jwk_repo) = self.jwk_repo {
            jwk_repo.delete_by_key_oid(key.oid).await?;
            jwk_repo
                .create_batch(build_jwk_inputs(&key, self.jwk_generator.as_ref())?)
                .await?;
        }

        self.refresh_runtime_key_ring().await?;
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

        self.refresh_runtime_key_ring().await?;
        Ok(key)
    }

    pub async fn revoke(&self, oid: Uuid) -> Result<Key, AppError> {
        let key = self
            .repo
            .revoke_by_oid(oid.into(), Utc::now())
            .await?
            .ok_or_else(|| AppError::from_code(KeyErrorCode::NotFound))?;
        self.refresh_runtime_key_ring().await?;
        Ok(key)
    }
}

fn prioritize_current_signing_key(jwks: &mut [KeyJwk], key_id: &str) {
    if let Some(position) = jwks
        .iter()
        .position(|binding| binding.jwk.key_id() == Some(key_id))
    {
        jwks[..=position].rotate_right(1);
    }
}

fn build_jwk_inputs(
    key: &Key,
    jwk_generator: &dyn KeyJwkGenerator,
) -> Result<Vec<CreateKeyJwkInput>, AppError> {
    let KeyData::Asymmetric(data) = &key.data else {
        return Ok(vec![]);
    };

    let key_id = Uuid::from(key.oid).to_string();
    let jwks = jwk_generator.generate(&data.private_key, &key_id, data.certificate.as_deref())?;

    jwks.into_iter()
        .map(|generated| {
            Ok(CreateKeyJwkInput {
                key_oid: key.oid,
                algorithm: generated.algorithm,
                jwk: generated.jwk,
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::prioritize_current_signing_key;
    use crate::domain::key::{KeyJwk, KeyJwkOid, KeyOid, PublicJwk};

    #[test]
    fn published_jwks_start_with_the_runtime_signing_key() {
        let binding = |kid: Uuid| KeyJwk {
            oid: KeyJwkOid(kid),
            key_oid: KeyOid(Uuid::new_v4()),
            algorithm: "RS256".parse().unwrap(),
            jwk: PublicJwk::Rsa {
                key_use: Some("sig".to_owned()),
                alg: Some("RS256".to_owned()),
                kid: Some(kid.to_string()),
                n: "modulus".to_owned(),
                e: "AQAB".to_owned(),
                x5c: None,
                x5t: None,
                x5t_s256: None,
            },
            created_at: Utc::now(),
        };
        let previous = Uuid::new_v4();
        let current = Uuid::new_v4();
        let another = Uuid::new_v4();
        let mut jwks = vec![binding(previous), binding(another), binding(current)];

        prioritize_current_signing_key(&mut jwks, &current.to_string());

        let published: Vec<_> = jwks.iter().map(|binding| binding.oid.0).collect();
        assert_eq!(published, vec![current, previous, another]);
    }
}
