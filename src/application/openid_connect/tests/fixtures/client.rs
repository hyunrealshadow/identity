use chrono::Utc;
use url::Url;

use identity_domain::{
    client::model::{Client, ClientOid, ClientProtocol},
    openid_connect::{
        GrantType, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
        OpenIdConnectClientPlatformType, OpenIdConnectClientSettings,
    },
};

pub(in crate::openid_connect) fn test_client(oid: ClientOid) -> Client {
    Client {
        oid,
        protocol: ClientProtocol::OpenIdConnect,
        name: "Example RP".to_string(),
        names: vec![],
        description: None,
        built_in: false,
        created_at: Utc::now(),
        updated_at: None,
    }
}

pub(in crate::openid_connect) fn test_metadata(
    request_uris: Option<Vec<Url>>,
    token_endpoint_auth_method: Option<&str>,
) -> OpenIdConnectClientMetadata {
    OpenIdConnectClientMetadata {
        post_logout_redirect_uris: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        response_types: None,
        grant_types: Some(vec![
            GrantType::AuthorizationCode,
            GrantType::Implicit,
            GrantType::RefreshToken,
        ]),
        contacts: None,
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        sector_identifier_uri: None,
        subject_type: None,
        id_token_signed_response_algs: None,
        id_token_encrypted_response_algs: None,
        id_token_encrypted_response_encs: None,
        userinfo_signed_response_algs: None,
        userinfo_encrypted_response_algs: None,
        userinfo_encrypted_response_encs: None,
        request_object_signing_algs: None,
        request_object_encryption_algs: None,
        request_object_encryption_encs: None,
        token_endpoint_auth_methods: token_endpoint_auth_method
            .map(|value| vec![value.parse().unwrap()]),
        token_endpoint_auth_signing_algs: None,
        default_max_age: None,
        require_auth_time: None,
        default_acr_values: None,
        initiate_login_uri: None,
        request_uris,
        settings: OpenIdConnectClientSettings {
            require_pushed_authorization_requests: false,
            allow_public_client_flow: token_endpoint_auth_method == Some("none"),
            ..OpenIdConnectClientSettings::default()
        },
    }
}

pub(in crate::openid_connect) fn test_platforms() -> Vec<OpenIdConnectClientPlatform> {
    vec![OpenIdConnectClientPlatform {
        platform: OpenIdConnectClientPlatformType::Web,
        redirect_uris: vec!["https://client.example.com/callback".to_owned()],
    }]
}

pub(in crate::openid_connect) fn test_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ]
}

/// Client settings and registered authentication methods varied independently.
pub(in crate::openid_connect) struct ConfiguredClientRepository {
    pub settings: OpenIdConnectClientSettings,
    pub methods: Vec<identity_domain::openid_connect::TokenEndpointAuthMethod>,
}

#[async_trait::async_trait]
impl identity_domain::openid_connect::OpenIdConnectClientRepository for ConfiguredClientRepository {
    async fn find_by_oid(
        &self,
        oid: ClientOid,
    ) -> Result<
        Option<identity_domain::openid_connect::OpenIdConnectClient>,
        identity_domain::openid_connect::OpenIdConnectClientRepositoryError,
    > {
        let mut metadata = test_metadata(None, None);
        metadata.settings = self.settings.clone();
        metadata.token_endpoint_auth_methods = Some(self.methods.clone());
        Ok(Some(
            identity_domain::openid_connect::OpenIdConnectClient::new(
                test_client(oid),
                metadata,
                test_platforms(),
                test_scopes(),
            )
            .unwrap(),
        ))
    }
}
