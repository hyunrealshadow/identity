use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::key::model::{Key, KeyData, KeyType};

#[derive(Debug, Error)]
pub enum KeyRepositoryError {
    #[error("failed to query key")]
    QueryFailed(#[source] sea_orm::DbErr),

    #[error("failed to list available keys")]
    ListAvailableFailed(#[source] sea_orm::DbErr),

    #[error("failed to serialize key data")]
    Serialize(#[source] serde_json::Error),

    #[error("failed to deserialize key data")]
    Deserialize(#[source] serde_json::Error),

    #[error("invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("certificate can only be attached to asymmetric keys")]
    CertificateRequiresAsymmetricKey,

    #[error("failed to create key")]
    CreateFailed(#[source] sea_orm::DbErr),

    #[error("failed to update key")]
    UpdateFailed(#[source] sea_orm::DbErr),
}

#[async_trait]
pub trait KeyRepository: Send + Sync {
    async fn find_by_oid(&self, oid: Uuid) -> Result<Option<Key>, KeyRepositoryError>;

    async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError>;

    async fn create(
        &self,
        key_type: KeyType,
        data: &KeyData,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Key, KeyRepositoryError>;

    async fn update_certificate_by_oid(
        &self,
        oid: Uuid,
        certificate_pem: &str,
    ) -> Result<Option<Key>, KeyRepositoryError>;

    async fn revoke_by_oid(
        &self,
        oid: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<Key>, KeyRepositoryError>;
}
