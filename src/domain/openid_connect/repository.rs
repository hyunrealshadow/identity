use super::model::client::{
    OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
};
use super::model::credential::{
    OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialOid,
    OpenIdConnectCredentialType,
};
use crate::auth::model::SessionOid;
use crate::client::model::Client;
use crate::client::model::ClientOid;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenIdConnectClientRepositoryError {
    #[error("failed to query openid connect client")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("openid connect metadata row is missing for client {0}")]
    MissingMetadata(ClientOid),

    #[error("failed to deserialize openid connect metadata")]
    DeserializeMetadata(#[source] serde_json::Error),

    #[error("failed to parse openid connect url")]
    ParseUrl(#[source] url::ParseError),

    #[error("failed to parse openid connect client platform")]
    ParseClientPlatform(
        #[source] crate::openid_connect::model::client::ParseOpenIdConnectClientPlatformKindError,
    ),

    #[error("failed to parse openid connect subject type")]
    ParseSubjectType(#[source] crate::openid_connect::model::provider::ParseSubjectTypeError),

    #[error("invalid openid connect client")]
    InvalidClient(#[source] crate::openid_connect::model::client::InvalidOpenIdConnectClientError),

    #[error("failed to parse client protocol")]
    ParseClientProtocol(#[source] crate::client::model::ParseClientProtocolError),

    #[error("openid connect client not found")]
    ClientNotFound,
}

#[derive(Debug, Clone)]
pub struct OpenIdConnectClientRegistration {
    pub client: Client,
    pub metadata: OpenIdConnectClientMetadata,
    pub platforms: Vec<OpenIdConnectClientPlatform>,
    pub assigned_scopes: Vec<String>,
    pub client_secret: Option<String>,
    pub credentials: Vec<OpenIdConnectCredentialData>,
    pub registration_access_token: String,
}

#[derive(Debug, Error)]
pub enum OpenIdConnectCredentialRepositoryError {
    #[error("failed to query openid connect credentials")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("openid connect credential owner is missing")]
    MissingClient,

    #[error("failed to deserialize openid connect credential data")]
    DeserializeData(#[source] serde_json::Error),

    #[error("failed to parse openid connect credential url")]
    ParseUrl(#[source] url::ParseError),

    #[error("failed to parse openid connect credential datetime")]
    ParseDateTime(#[source] chrono::ParseError),

    #[error("failed to parse openid connect credential type")]
    ParseCredentialType(
        #[source] crate::openid_connect::model::credential::ParseOpenIdConnectCredentialTypeError,
    ),
}

#[async_trait::async_trait]
pub trait OpenIdConnectClientRepository: Send + Sync {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;

    async fn find_frontchannel_logout_clients_by_session_oid(
        &self,
        _session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Vec::new())
    }

    async fn find_backchannel_logout_clients_by_session_oid(
        &self,
        _session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
pub trait OpenIdConnectClientRegistrationRepository: Send + Sync {
    async fn create(
        &self,
        registration: OpenIdConnectClientRegistration,
    ) -> Result<ClientOid, OpenIdConnectClientRepositoryError>;

    async fn find_by_registration_access_token(
        &self,
        client_oid: ClientOid,
        token: &str,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;

    async fn delete_by_oid(
        &self,
        client_oid: ClientOid,
    ) -> Result<(), OpenIdConnectClientRepositoryError>;
}

#[async_trait::async_trait]
pub trait OpenIdConnectCredentialRepository: Send + Sync {
    async fn find_by_oid(
        &self,
        oid: OpenIdConnectCredentialOid,
    ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>;

    async fn find_by_client_oid_and_type(
        &self,
        client_oid: ClientOid,
        type_: OpenIdConnectCredentialType,
    ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>;

    async fn find_first_encryption_key(
        &self,
        client_oid: ClientOid,
    ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        let types = vec![
            OpenIdConnectCredentialType::ClientPublicKey,
            OpenIdConnectCredentialType::ClientJsonWebKeySet,
        ];
        for type_ in types {
            let results = self.find_by_client_oid_and_type(client_oid, type_).await?;
            if let Some(credential) = results.into_iter().next() {
                return Ok(Some(credential));
            }
        }
        Ok(None)
    }
}
