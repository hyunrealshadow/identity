use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::model::{ClientAuthorization, ClientAuthorizationType, ConsentState, SelectionSource};
use crate::auth::model::SessionOid;
use crate::client::model::ClientOid;

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

    async fn update_authorization_request_selection(
        &self,
        oid: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn record_authorization_request_consent(
        &self,
        oid: Uuid,
        consent_state: ConsentState,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn mark_authorization_request_completed(
        &self,
        oid: Uuid,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn revoke_access_tokens_for_authorization_code(
        &self,
        authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError>;

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientAuthorizationRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ClientAuthorizationRepositoryError {
    #[error("failed to query client authorization")]
    QueryFailed(#[source] sea_orm::DbErr),
}
