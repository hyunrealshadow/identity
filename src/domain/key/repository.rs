use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::key::{Key, KeyData, KeyOid, KeyType};

#[derive(Debug, Error)]
pub enum KeyRepositoryError {
    #[error("failed to query key")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to list available keys")]
    ListAvailableFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to serialize key data")]
    Serialize(#[source] serde_json::Error),

    #[error("failed to deserialize key data")]
    Deserialize(#[source] serde_json::Error),

    #[error("invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("certificate can only be attached to asymmetric keys")]
    CertificateRequiresAsymmetricKey,

    #[error("failed to create key")]
    CreateFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to update key")]
    UpdateFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[async_trait]
pub trait KeyRepository: Send + Sync {
    async fn find_by_oid(&self, oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError>;

    async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;

    async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;

    async fn create(
        &self,
        key_type: KeyType,
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
