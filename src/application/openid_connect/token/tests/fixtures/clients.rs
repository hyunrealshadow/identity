use super::*;
use crate::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};

pub(in crate::openid_connect) struct InMemoryClientRepository;
pub(in crate::openid_connect) struct PublicFlowClientRepository;
pub(in crate::openid_connect) struct ScopedClaimsClientRepository;
pub(in crate::openid_connect) struct RestrictedGrantClientRepository {
    pub(in crate::openid_connect) grant_types: Vec<identity_domain::openid_connect::GrantType>,
}

/// A client whose registration declares `token_endpoint_auth_method: none`;
/// unlike `PublicFlowClientRepository` it does not enable the browser public
/// client flow.
pub(in crate::openid_connect) struct RegisteredPublicClientRepository;
pub(in crate::openid_connect) struct AuthMethodClientRepository {
    pub(in crate::openid_connect) method: &'static str,
    pub(in crate::openid_connect) signing_alg: Option<&'static str>,
}

#[async_trait]
impl OpenIdConnectClientRepository for InMemoryClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                test_metadata(None, Some("client_secret_basic")),
                test_platforms(),
                test_scopes(),
            )
            .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for RestrictedGrantClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.grant_types = Some(self.grant_types.clone());

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for RegisteredPublicClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let metadata = test_metadata(None, Some("none"));

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for PublicFlowClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.settings.allow_public_client_flow = true;

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for ScopedClaimsClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.settings.include_scoped_claims_in_id_token = true;

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for AuthMethodClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some(self.method));
        metadata.token_endpoint_auth_signing_alg =
            self.signing_alg.map(|value| value.parse().unwrap());

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}
