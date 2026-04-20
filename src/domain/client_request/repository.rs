use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::model::{ClientRequest, ClientRequestType};
use crate::domain::client::model::ClientOid;

#[async_trait]
pub trait ClientRequestRepository: Send + Sync {
    async fn create(
        &self,
        client_oid: ClientOid,
        type_: ClientRequestType,
        data: serde_json::Value,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientRequest, ClientRequestRepositoryError>;

    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError>;

    async fn find_refresh_token_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError>;

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientRequestRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ClientRequestRepositoryError {
    #[error("failed to query client request")]
    QueryFailed(#[source] sea_orm::DbErr),
}
