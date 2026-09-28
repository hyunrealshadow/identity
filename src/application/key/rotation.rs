use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use crate::{error::AppError, key::runtime::RuntimeKeyRingProvider};
use identity_domain::key::{Key, KeyData, KeyOid};

use super::asymmetric::GeneratedKeyJwk;

pub const KEY_LIFETIME: Duration = Duration::days(90);
pub const KEY_ROTATION_AGE: Duration = Duration::days(60);

pub struct RotationMaterial {
    pub data: KeyData,
    pub jwks: Vec<GeneratedKeyJwk>,
}

pub trait KeyRotationMaterialGenerator: Send + Sync {
    fn generate(&self, previous: &Key) -> Result<RotationMaterial, AppError>;
}

#[async_trait]
pub trait KeyRotationRepository: Send + Sync {
    async fn list_due(&self, now: DateTime<Utc>) -> Result<Vec<Key>, AppError>;

    /// Inserts the successor, its JWK bindings and marks the predecessor in
    /// one transaction. A competing instance returns false after rechecking.
    async fn rotate_if_due(
        &self,
        previous_oid: KeyOid,
        material: RotationMaterial,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
}

pub struct KeyRotationService {
    repository: Arc<dyn KeyRotationRepository>,
    generator: Arc<dyn KeyRotationMaterialGenerator>,
    runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
}

impl KeyRotationService {
    pub fn new(
        repository: Arc<dyn KeyRotationRepository>,
        generator: Arc<dyn KeyRotationMaterialGenerator>,
        runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
    ) -> Self {
        Self {
            repository,
            generator,
            runtime_key_ring,
        }
    }

    pub async fn maintain(&self) -> Result<u64, AppError> {
        let now = Utc::now();
        let mut rotated = 0;
        let mut first_error = None;
        for previous in self.repository.list_due(now).await? {
            let result = match self.generator.generate(&previous) {
                Ok(material) => {
                    self.repository
                        .rotate_if_due(previous.oid, material, now)
                        .await
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(changed) => {
                    rotated += u64::from(changed);
                    if changed {
                        tracing::info!(key_oid = %uuid::Uuid::from(previous.oid), "key rotated");
                    }
                }
                Err(error) => {
                    tracing::error!(key_oid = %uuid::Uuid::from(previous.oid), error = %error, "key rotation failed");
                    first_error.get_or_insert(error);
                }
            }
        }
        if rotated > 0 {
            self.runtime_key_ring.refresh_value().await?;
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(rotated),
        }
    }
}
