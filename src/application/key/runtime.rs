use std::sync::Arc;

use async_trait::async_trait;

use crate::{application::error::AppError, domain::data_protection::KeyRing};
use identity_domain::key::JwaSigningAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSigningKey {
    pub key_id: String,
    pub private_key_pem: String,
    pub algorithm: JwaSigningAlgorithm,
}

pub struct RuntimeKeyRing {
    data_protection: KeyRing,
    signing_key: Option<RuntimeSigningKey>,
}

impl RuntimeKeyRing {
    #[must_use]
    pub fn new(data_protection: KeyRing, signing_key: Option<RuntimeSigningKey>) -> Self {
        Self {
            data_protection,
            signing_key,
        }
    }

    #[must_use]
    pub fn data_protection(&self) -> &KeyRing {
        &self.data_protection
    }

    #[must_use]
    pub fn signing_key(&self) -> Option<&RuntimeSigningKey> {
        self.signing_key.as_ref()
    }
}

#[async_trait]
pub trait RuntimeKeyRingProvider: Send + Sync {
    fn current_value(&self) -> Arc<RuntimeKeyRing>;

    async fn refresh_value(&self) -> Result<(), AppError>;
}
