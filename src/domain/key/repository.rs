use std::error::Error as StdError;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Error as SerdeJsonError;
use thiserror::Error;

use crate::key::{Key, KeyData, KeyOid};

#[derive(Debug, Error)]
pub enum KeyRepositoryError {
    #[error("failed to query key")]
    QueryFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to list available keys")]
    ListAvailableFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to serialize key data")]
    Serialize(#[source] SerdeJsonError),

    #[error("failed to deserialize key data")]
    Deserialize(#[source] SerdeJsonError),

    #[error("invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("certificate can only be attached to asymmetric keys")]
    CertificateRequiresAsymmetricKey,

    #[error("failed to create key")]
    CreateFailed(#[source] Box<dyn StdError + Send + Sync>),

    #[error("failed to update key")]
    UpdateFailed(#[source] Box<dyn StdError + Send + Sync>),
}

#[async_trait]
pub trait KeyRepository: Send + Sync {
    async fn find_by_oid(&self, oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError>;

    /// Lists unrevoked, unexpired asymmetric keys usable for new signatures.
    async fn list_active_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;

    /// Lists unrevoked symmetric keys, including expired keys retained to
    /// decrypt payloads created before their encryption lifetime ended.
    async fn list_decryptable_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;

    async fn create(
        &self,
        data: &KeyData,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Key, KeyRepositoryError>;

    async fn update_certificate_by_oid(
        &self,
        oid: KeyOid,
        certificate_pem: &str,
    ) -> Result<Option<Key>, KeyRepositoryError>;

    async fn revoke_by_oid(
        &self,
        oid: KeyOid,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<Key>, KeyRepositoryError>;
}
