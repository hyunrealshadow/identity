use super::*;
use crate::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};

pub(in crate::openid_connect) struct MissingClientRepository;

pub(in crate::openid_connect) struct FoundClientRepository;

pub(in crate::openid_connect) struct RequestUriClientRepository {
    pub(in crate::openid_connect) request_uris: Vec<Url>,
}

pub(in crate::openid_connect) struct ScopedClientRepository {
    pub(in crate::openid_connect) assigned_scopes: Vec<String>,
}

pub(in crate::openid_connect) const TEST_CLIENT_ID: Uuid = Uuid::nil();

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
