use super::*;
use crate::application::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};

pub(crate) struct MissingClientRepository;

pub(crate) struct FoundClientRepository;

pub(crate) struct RequestUriClientRepository {
    pub(crate) request_uris: Vec<Url>,
}

pub(crate) struct ScopedClientRepository {
    pub(crate) assigned_scopes: Vec<String>,
}

pub(crate) const TEST_CLIENT_ID: Uuid = Uuid::nil();

#[async_trait]
impl OpenIdConnectClientRepository for MissingClientRepository {
    async fn find_by_oid(
        &self,
        _oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(None)
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for FoundClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                test_metadata(None, None),
                test_platforms(),
                test_scopes(),
            )
            .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for ScopedClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                test_metadata(None, None),
                test_platforms(),
                self.assigned_scopes.clone(),
            )
            .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for RequestUriClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                test_metadata(Some(self.request_uris.clone()), None),
                test_platforms(),
                test_scopes(),
            )
            .unwrap(),
        ))
    }
}
