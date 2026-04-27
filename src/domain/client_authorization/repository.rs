use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::model::{ClientAuthorization, ClientAuthorizationType};
use crate::domain::client::model::ClientOid;

#[async_trait]
pub trait ClientAuthorizationRepository: Send + Sync {
    async fn create(
        &self,
        client_oid: ClientOid,
        type_: ClientAuthorizationType,
        data: serde_json::Value,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError>;

    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError>;

    async fn find_refresh_token_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError>;

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientAuthorizationRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ClientAuthorizationRepositoryError {
    #[error("failed to query client authorization")]
    QueryFailed(#[source] sea_orm::DbErr),
}
