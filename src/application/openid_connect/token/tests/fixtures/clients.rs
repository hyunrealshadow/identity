use identity_domain::{
    key::{JwaSigningAlgorithm, JwsAlgorithm},
    openid_connect::{GrantType, TokenEndpointAuthMethod},
};

use crate::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};

use super::*;

pub(in crate::openid_connect) struct InMemoryClientRepository;
pub(in crate::openid_connect) struct IdTokenAlgorithmClientRepository {
    pub(in crate::openid_connect) algorithm: JwaSigningAlgorithm,
}
pub(in crate::openid_connect) struct ScopedClaimsClientRepository;
pub(in crate::openid_connect) struct AccessClaimsClientRepository;
pub(in crate::openid_connect) struct RestrictedGrantClientRepository {
    pub(in crate::openid_connect) grant_types: Vec<GrantType>,
}

/// A client whose registration declares `token_endpoint_auth_method: none`.
pub(in crate::openid_connect) struct RegisteredPublicClientRepository;
pub(in crate::openid_connect) struct MixedClientRepository;
pub(in crate::openid_connect) struct MachineClientRepository;
pub(in crate::openid_connect) struct MachineAlgorithmClientRepository {
    pub(in crate::openid_connect) algorithm: JwaSigningAlgorithm,
    pub(in crate::openid_connect) include_access_claims: bool,
}
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
impl OpenIdConnectClientRepository for IdTokenAlgorithmClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.id_token_signed_response_algs =
            Some(vec![JwsAlgorithm::Asymmetric(self.algorithm)]);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
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
        let mut metadata = test_metadata(None, Some("none"));
        metadata.settings.allow_public_client_flow = true;

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for MixedClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.settings.allow_public_client_flow = true;
        metadata.token_endpoint_auth_methods = Some(vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::None,
        ]);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for MachineClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.grant_types = Some(vec![GrantType::ClientCredentials]);
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                metadata,
                test_platforms(),
                vec!["account.read".to_owned(), "session.read".to_owned()],
            )
            .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for MachineAlgorithmClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.grant_types = Some(vec![GrantType::ClientCredentials]);
        metadata.id_token_signed_response_algs =
            Some(vec![JwsAlgorithm::Asymmetric(self.algorithm)]);
        metadata.settings.include_scoped_claims_in_access_token = self.include_access_claims;
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                metadata,
                test_platforms(),
                vec!["account.read".to_owned()],
            )
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
impl OpenIdConnectClientRepository for AccessClaimsClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.settings.include_scoped_claims_in_access_token = true;

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
        metadata.token_endpoint_auth_signing_algs =
            self.signing_alg.map(|value| vec![value.parse().unwrap()]);

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}
