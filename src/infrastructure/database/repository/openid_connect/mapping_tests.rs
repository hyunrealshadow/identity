use chrono::Utc;
use identity_domain::openid_connect::OpenIdConnectClientRepositoryError;
use serde_json::json;

use super::mapping::{
    deserialize_optional_string_vec, parse_optional_url, parse_optional_urls, to_metadata,
    to_platform,
};
use super::registration::cors_origins_for_client;
use crate::{
    domain::openid_connect::{
        OpenIdConnectClientPlatform, OpenIdConnectClientPlatformType, OpenIdConnectClientSettings,
    },
    infrastructure::database::entity::{client_openid_connect, client_openid_connect_platform},
};

#[test]
fn materialized_cors_origins_follow_client_settings_and_redirects() {
    let platforms = vec![
        OpenIdConnectClientPlatform {
            platform: OpenIdConnectClientPlatformType::Web,
            redirect_uris: [
                "https://rp.example.com/callback",
                "https://rp.example.com/another",
                "http://localhost:3000/callback",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        },
        OpenIdConnectClientPlatform {
            platform: OpenIdConnectClientPlatformType::Native,
            redirect_uris: vec!["com.example.app:/callback".to_owned()],
        },
    ];
    let mut settings = OpenIdConnectClientSettings::default();
    assert!(cors_origins_for_client(&settings, &platforms).is_empty());

    settings.cors_enabled = true;
    assert_eq!(
        cors_origins_for_client(&settings, &platforms),
        ["http://localhost:3000", "https://rp.example.com"]
    );
}

#[test]
fn parses_json_array_to_optional_vec() {
    let values = deserialize_optional_string_vec(Some(&json!(["a", "b"]))).unwrap();
    assert_eq!(values, Some(vec!["a".to_string(), "b".to_string()]));
}

#[test]
fn parses_url_field() {
    let url = parse_optional_url(Some("https://example.com/callback")).unwrap();
    assert_eq!(url.unwrap().as_str(), "https://example.com/callback");
}

#[test]
fn parses_url_arrays_without_dropping_entries() {
    let urls = parse_optional_urls(Some(&json!([
        "https://example.com/a",
        "https://example.com/b"
    ])))
    .unwrap();
    assert_eq!(urls.unwrap().len(), 2);
}

#[test]
fn maps_logout_and_multivalue_metadata() {
    let metadata = to_metadata(client_openid_connect::Model {
        id: 1,
        client_id: 2,
        post_logout_redirect_uris: None,
        frontchannel_logout_uri: Some("https://rp.example.com/frontchannel_logout".to_owned()),
        frontchannel_logout_session_required: Some(true),
        backchannel_logout_uri: Some("https://rp.example.com/backchannel_logout".to_owned()),
        backchannel_logout_session_required: Some(true),
        response_types: None,
        grant_types: None,
        contacts: None,
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        sector_identifier_uri: None,
        subject_type: None,
        id_token_signed_response_algs: Some(json!(["RS256", "ES256"])),
        id_token_encrypted_response_algs: None,
        id_token_encrypted_response_encs: None,
        userinfo_signed_response_algs: None,
        userinfo_encrypted_response_algs: None,
        userinfo_encrypted_response_encs: None,
        request_object_signing_algs: None,
        request_object_encryption_algs: None,
        request_object_encryption_encs: None,
        token_endpoint_auth_methods: Some(json!(["client_secret_basic", "none"])),
        token_endpoint_auth_signing_algs: None,
        default_max_age: None,
        require_auth_time: None,
        default_acr_values: None,
        initiate_login_uri: None,
        request_uris: None,
        settings: json!({}),
        created_at: Utc::now().into(),
        updated_at: None,
    })
    .unwrap();

    assert_eq!(
        metadata.frontchannel_logout_uri.unwrap().as_str(),
        "https://rp.example.com/frontchannel_logout"
    );
    assert_eq!(metadata.frontchannel_logout_session_required, Some(true));
    assert_eq!(
        metadata.backchannel_logout_uri.unwrap().as_str(),
        "https://rp.example.com/backchannel_logout"
    );
    assert_eq!(metadata.backchannel_logout_session_required, Some(true));
    assert_eq!(
        metadata
            .id_token_signed_response_algs
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["RS256", "ES256"]
    );
    assert_eq!(
        metadata
            .token_endpoint_auth_methods
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["client_secret_basic", "none"]
    );
}

#[test]
fn maps_client_openid_connect_platform_redirect_uris() {
    let platform = to_platform(client_openid_connect_platform::Model {
        id: 1,
        client_id: 2,
        platform: "web".to_string(),
        redirect_uris: Some(json!(["http://localhost:53000"])),
        created_at: Utc::now().into(),
        updated_at: None,
    })
    .unwrap();

    assert_eq!(platform.platform, OpenIdConnectClientPlatformType::Web);
    assert_eq!(platform.redirect_uris[0], "http://localhost:53000");
}

#[test]
fn rejects_unknown_client_openid_connect_platform() {
    let error = to_platform(client_openid_connect_platform::Model {
        id: 1,
        client_id: 2,
        platform: "ios".to_string(),
        redirect_uris: Some(json!(["com.example.app:/callback"])),
        created_at: Utc::now().into(),
        updated_at: None,
    })
    .unwrap_err();

    assert!(matches!(
        error,
        OpenIdConnectClientRepositoryError::ParseClientPlatform(_)
    ));
}
