use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use identity_application::{
    error::AppError,
    key::runtime::{RuntimeKeyRing, RuntimeKeyRingProvider, RuntimeSigningKey},
    observability::{BusinessEvent, EventValue, event_sink},
    openid_connect::provider::SigningAlgorithmDetector,
    setting::runtime::RefreshableSetting,
};
use identity_domain::{
    data_protection::KeyRing,
    key::{KeyData, KeyJwkRepository, repository::KeyRepository},
};
use sea_orm::DatabaseConnection;
use tracing::info_span;
use uuid::Uuid;

use crate::{
    crypto::signing_algorithm::SigningAlgorithmDetectorImpl,
    database::repository::{key::KeyRepositoryImpl, key_jwk::KeyJwkRepositoryImpl},
};

pub struct CachedRuntimeKeyRingProvider {
    key_repo: Arc<dyn KeyRepository>,
    key_jwk_repo: Arc<dyn KeyJwkRepository>,
    signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    value: RwLock<Arc<RuntimeKeyRing>>,
}

impl CachedRuntimeKeyRingProvider {
    pub async fn new(db: DatabaseConnection) -> Result<Self, AppError> {
        let provider = Self {
            key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
            key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db)),
            signing_algorithm_detector: Arc::new(SigningAlgorithmDetectorImpl),
            value: RwLock::new(Arc::new(RuntimeKeyRing::new(KeyRing::new(vec![]), None))),
        };
        provider.refresh().await?;
        Ok(provider)
    }

    async fn refresh(&self) -> Result<(), AppError> {
        let span = info_span!("key.ring.refresh");
        let _entered = span.enter();
        let symmetric_keys = self.key_repo.list_decryptable_symmetric().await?;
        let asymmetric_keys = self.key_repo.list_active_asymmetric().await?;
        let mut signing_key = None;

        for key in asymmetric_keys {
            let KeyData::Asymmetric(data) = &key.data else {
                continue;
            };
            let Some(algorithm) = self
                .signing_algorithm_detector
                .detect(&key)
                .into_iter()
                .next()
            else {
                continue;
            };
            let Some(binding) = self
                .key_jwk_repo
                .find_active_by_key_oid_and_algorithm(key.oid, algorithm)
                .await?
            else {
                continue;
            };

            signing_key = Some(RuntimeSigningKey {
                key_id: Uuid::from(binding.oid).to_string(),
                private_key_pem: data.private_key.clone(),
                algorithm,
            });
            break;
        }

        let previous_signing_key = self
            .current_value()
            .signing_key()
            .map(|key| key.key_id.clone());
        let next_signing_key = signing_key.as_ref().map(|key| key.key_id.clone());
        let value = Arc::new(RuntimeKeyRing::new(
            KeyRing::new(symmetric_keys),
            signing_key,
        ));
        *self
            .value
            .write()
            .unwrap_or_else(|error| error.into_inner()) = value;
        if previous_signing_key != next_signing_key {
            let mut event = BusinessEvent::business("key.ring.changed").outcome("applied");
            if let Some(key_id) = next_signing_key {
                event = event.attribute("key_id", EventValue::Text(key_id));
            }
            event_sink().emit(event);
        }
        Ok(())
    }
}

#[async_trait]
impl RuntimeKeyRingProvider for CachedRuntimeKeyRingProvider {
    fn current_value(&self) -> Arc<RuntimeKeyRing> {
        self.value
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await
    }
}

#[async_trait]
impl RefreshableSetting for CachedRuntimeKeyRingProvider {
    fn key(&self) -> &'static str {
        "runtime.key_ring"
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await
    }
}
