use identity_domain::{
    auth::ACR_AAL2,
    openid_connect::{GrantType, OAuthProtocolVersion, TokenEndpointAuthMethod},
};

use crate::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};

use super::*;

pub(in crate::openid_connect) struct MissingClientRepository;

pub(in crate::openid_connect) struct FoundClientRepository;
pub(in crate::openid_connect) struct DefaultsClientRepository;
pub(in crate::openid_connect) struct LegacyClientRepository;

pub(in crate::openid_connect) struct PublicClientRepository;
pub(in crate::openid_connect) struct OAuth20PublicClientRepository;

pub(in crate::openid_connect) struct RequestUriClientRepository {
    pub(in crate::openid_connect) request_uris: Vec<Url>,
}

pub(in crate::openid_connect) struct InitiateLoginClientRepository {
    pub(in crate::openid_connect) initiate_login_uri: Url,
}

pub(in crate::openid_connect) struct ScopedClientRepository {
    pub(in crate::openid_connect) assigned_scopes: Vec<String>,
}

pub(in crate::openid_connect) struct RestrictedGrantClientRepository {
    pub(in crate::openid_connect) grant_types: Vec<GrantType>,
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
impl OpenIdConnectClientRepository for RestrictedGrantClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, None);
        metadata.grant_types = Some(self.grant_types.clone());

        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for FoundClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, None);
        metadata.settings.oauth_version = Some(OAuthProtocolVersion::V2_1);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for DefaultsClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, None);
        metadata.default_max_age = Some(300);
        metadata.default_acr_values = Some(vec![ACR_AAL2.to_owned()]);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for LegacyClientRepository {
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
impl OpenIdConnectClientRepository for PublicClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, None);
        metadata.settings.allow_public_client_flow = true;
        metadata.token_endpoint_auth_methods = Some(vec![TokenEndpointAuthMethod::None]);
        metadata.settings.oauth_version = Some(OAuthProtocolVersion::V2_1);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for OAuth20PublicClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, None);
        metadata.settings.allow_public_client_flow = true;
        metadata.token_endpoint_auth_methods = Some(vec![TokenEndpointAuthMethod::None]);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
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

#[async_trait]
impl OpenIdConnectClientRepository for InitiateLoginClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let mut metadata = test_metadata(None, None);
        metadata.initiate_login_uri = Some(self.initiate_login_uri.clone());
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    }
}
