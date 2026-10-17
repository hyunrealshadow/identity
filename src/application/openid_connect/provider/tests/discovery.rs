use super::*;

#[tokio::test]
async fn normalizes_plain_domain_to_https_issuer() {
    let service = OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                domain: Some("identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await;

    let issuer = service.issuer().unwrap();

    assert_eq!(issuer.as_str(), "https://identity.example.com/");
}

#[tokio::test]
async fn assembles_discovery_document_from_issuer_and_capabilities() {
    let service = OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                domain: Some("https://identity.example.com/issuer1/".to_owned()),
                login_domain: None,
                login_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await;

    let metadata = service.discovery_metadata().await.unwrap();

    assert!(metadata.request_uri_parameter_supported);
    assert!(metadata.require_request_uri_registration);
    assert_eq!(
        metadata
            .pushed_authorization_request_endpoint
            .as_ref()
            .unwrap()
            .as_str(),
        "https://identity.example.com/issuer1/oauth2/par"
    );
    assert!(!metadata.require_pushed_authorization_requests);
    assert_eq!(
        metadata.issuer.as_str(),
        "https://identity.example.com/issuer1"
    );
    assert_eq!(
        metadata.authorization_endpoint.as_str(),
        "https://identity.example.com/issuer1/oauth2/authorize"
    );
    assert_eq!(
        metadata.jwks_uri.as_str(),
        "https://identity.example.com/issuer1/.well-known/keys"
    );
    assert_eq!(
        metadata.end_session_endpoint.unwrap().as_str(),
        "https://identity.example.com/issuer1/oauth2/logout"
    );
    assert_eq!(
        metadata.check_session_iframe.unwrap().as_str(),
        "https://identity.example.com/issuer1/oauth2/check_session"
    );
    assert_eq!(metadata.frontchannel_logout_supported, Some(true));
    assert_eq!(metadata.frontchannel_logout_session_supported, Some(true));
    assert_eq!(metadata.backchannel_logout_supported, Some(true));
    assert_eq!(metadata.backchannel_logout_session_supported, Some(true));
    assert_eq!(
        metadata.response_types_supported,
        vec![
            "code",
            "id_token",
            "id_token token",
            "code id_token",
            "code token",
            "code id_token token"
        ]
    );
}

#[tokio::test]
async fn discovery_advertises_registration_endpoint_when_enabled() {
    let service = OpenIdProviderService::for_test_with_registration(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                domain: Some("https://identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await;

    let metadata = service.discovery_metadata().await.unwrap();

    assert_eq!(
        metadata.registration_endpoint.unwrap().as_str(),
        "https://identity.example.com/oauth2/register"
    );
}
