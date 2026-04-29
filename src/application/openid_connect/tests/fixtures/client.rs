use chrono::Utc;
use url::Url;

use identity_domain::{
    client::model::{Client, ClientOid, ClientProtocol},
    openid_connect::{
        OpenIdConnectClientMetadata, OpenIdConnectClientPlatform, OpenIdConnectClientPlatformType,
        OpenIdConnectClientSettings,
    },
};

pub(in crate::openid_connect) fn test_client(oid: ClientOid) -> Client {
    Client {
        oid,
        protocol: ClientProtocol::OpenIdConnect,
        name: "Example RP".to_string(),
        names: vec![],
        description: None,
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
        response_types: None,
        grant_types: None,
        contacts: None,
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        sector_identifier_uri: None,
        subject_type: None,
        id_token_signed_response_alg: None,
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        request_object_signing_alg: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        token_endpoint_auth_method: token_endpoint_auth_method.map(str::to_owned),
        token_endpoint_auth_signing_alg: None,
        default_max_age: None,
        require_auth_time: None,
        default_acr_values: None,
        initiate_login_uri: None,
        request_uris,
        settings: OpenIdConnectClientSettings::default(),
    }
}

pub(in crate::openid_connect) fn test_platforms() -> Vec<OpenIdConnectClientPlatform> {
    vec![OpenIdConnectClientPlatform {
        platform: OpenIdConnectClientPlatformType::Web,
        redirect_uris: vec![Url::parse("https://client.example.com/callback").unwrap()],
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
