use std::sync::Arc;

use chrono::Utc;
use identity_domain::{
    client::model::{Client, ClientOid, ClientProtocol},
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
        OpenIdConnectClientPlatformType, OpenIdConnectClientRegistration,
        OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepositoryError,
    },
    setting::DynamicClientRegistrationSetting,
};
use url::Url;
use uuid::Uuid;

use crate::{
    application::setting::runtime::SettingProvider,
    openid_connect::registration::{
        DynamicClientRegistrationRequest, DynamicClientRegistrationService,
    },
    openid_connect::tests::fixtures::mocks::MockOpenIdConnectClientRegistrationRepository,
};

struct TestRegistrationSetting(bool);

impl SettingProvider<DynamicClientRegistrationSetting> for TestRegistrationSetting {
    fn current_value(&self) -> Arc<bool> {
        Arc::new(self.0)
    }
}

/// Creates a MockOpenIdConnectClientRegistrationRepository that captures the
/// registration passed to `create` and supports setting a found client and
/// tracking deletions.
fn capturing_registration_repo(
    captured: Arc<std::sync::Mutex<Option<OpenIdConnectClientRegistration>>>,
    deleted: Arc<std::sync::Mutex<Vec<ClientOid>>>,
) -> MockOpenIdConnectClientRegistrationRepository {
    let mut mock = MockOpenIdConnectClientRegistrationRepository::new();
    let c = captured.clone();
    mock.expect_create()
        .returning(move |registration: OpenIdConnectClientRegistration| {
            *c.lock().unwrap() = Some(registration);
            Ok(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
        });
    // find_by_registration_access_token: default returns None (no client found)
    // Tests that need a found client will set up their own mock.
    mock.expect_find_by_registration_access_token()
        .returning(|_client_oid: ClientOid, _token: &str| Ok(None));
    let d = deleted.clone();
    mock.expect_delete_by_oid()
        .returning(move |client_oid: ClientOid| {
            d.lock().unwrap().push(client_oid);
            Ok(())
        });
    mock
}

fn issuer() -> Url {
    Url::parse("https://identity.example.com").unwrap()
}

fn registered_client(client_oid: ClientOid) -> OpenIdConnectClient {
    OpenIdConnectClient::new(
        Client {
            oid: client_oid,
            protocol: ClientProtocol::OpenIdConnect,
            name: "Dynamic Client".to_owned(),
            names: vec![],
            description: None,
            created_at: Utc::now(),
            updated_at: None,
        },
        OpenIdConnectClientMetadata {
            post_logout_redirect_uris: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
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
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: Default::default(),
        },
        vec![OpenIdConnectClientPlatform {
            platform: OpenIdConnectClientPlatformType::Web,
            redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
        }],
        vec!["openid".to_owned()],
    )
    .unwrap()
}

#[tokio::test]
async fn register_rejects_requests_when_dynamic_registration_is_disabled() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(false)),
        repo.clone(),
    );

    let error = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 25000);
    assert!(captured.lock().unwrap().is_none());
}

#[tokio::test]
async fn register_maps_supported_client_metadata_and_generates_secret() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    let response = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                response_types: Some(vec!["code".to_owned()]),
                grant_types: Some(vec![
                    "authorization_code".to_owned(),
                    "refresh_token".to_owned(),
                ]),
                application_type: Some("web".to_owned()),
                contacts: Some(vec!["ops@example.com".to_owned()]),
                client_name: Some("Example RP".to_owned()),
                logo_uri: Some(Url::parse("https://rp.example.com/logo.png").unwrap()),
                client_uri: Some(Url::parse("https://rp.example.com").unwrap()),
                policy_uri: Some(Url::parse("https://rp.example.com/policy").unwrap()),
                tos_uri: Some(Url::parse("https://rp.example.com/tos").unwrap()),
                post_logout_redirect_uris: Some(vec![
                    Url::parse("https://rp.example.com/logout").unwrap(),
                ]),
                frontchannel_logout_uri: Some(
                    Url::parse("https://rp.example.com/frontchannel_logout").unwrap(),
                ),
                frontchannel_logout_session_required: Some(true),
                backchannel_logout_uri: Some(
                    Url::parse("https://rp.example.com/backchannel_logout").unwrap(),
                ),
                backchannel_logout_session_required: Some(true),
                subject_type: Some("pairwise".to_owned()),
                id_token_signed_response_alg: Some("ES256".to_owned()),
                token_endpoint_auth_method: Some("client_secret_post".to_owned()),
                token_endpoint_auth_signing_alg: Some("HS256".to_owned()),
                default_max_age: Some(3600),
                require_auth_time: Some(true),
                default_acr_values: Some(vec!["1".to_owned()]),
                initiate_login_uri: Some(Url::parse("https://rp.example.com/login").unwrap()),
                request_uris: Some(vec![
                    Url::parse("https://rp.example.com/request.jwt").unwrap(),
                ]),
                scope: Some("openid profile email".to_owned()),
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap();

    assert_eq!(response.client_id, "11111111-1111-1111-1111-111111111111");
    assert!(response.registration_access_token.is_some());
    assert_eq!(
        response.registration_client_uri.unwrap().as_str(),
        "https://identity.example.com/oauth2/register/11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(response.client_name.as_deref(), Some("Example RP"));
    assert_eq!(
        response.initiate_login_uri.as_ref().unwrap().as_str(),
        "https://rp.example.com/login"
    );
    assert_eq!(
        response.token_endpoint_auth_method.as_deref(),
        Some("client_secret_post")
    );
    assert!(
        response
            .client_secret
            .as_ref()
            .is_some_and(|value| value.len() >= 32)
    );
    assert!(response.client_secret_expires_at.is_some());

    let captured_val = captured.lock().unwrap().clone().unwrap();
    assert_eq!(captured_val.client.name, "Example RP");
    assert_eq!(captured_val.platforms[0].platform.to_string(), "web");
    assert_eq!(
        captured_val.metadata.subject_type.unwrap().to_string(),
        "pairwise"
    );
    assert_eq!(
        captured_val.metadata.post_logout_redirect_uris.unwrap()[0].as_str(),
        "https://rp.example.com/logout"
    );
    assert_eq!(
        captured_val.metadata.initiate_login_uri.unwrap().as_str(),
        "https://rp.example.com/login"
    );
    assert_eq!(
        captured_val.assigned_scopes,
        vec!["openid", "profile", "email"]
    );
    assert!(captured_val.client_secret.is_some());
    assert!(!captured_val.registration_access_token.is_empty());
    assert_eq!(
        captured_val.metadata.settings.skip_consent,
        cfg!(feature = "oidc-conformance")
    );
}

#[tokio::test]
async fn register_defaults_to_supported_oidc_scopes_when_scope_is_omitted() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    let response = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.scope.as_deref(),
        Some("openid profile email address phone offline_access")
    );

    let captured_val = captured.lock().unwrap().clone().unwrap();
    assert_eq!(
        captured_val.assigned_scopes,
        vec![
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access"
        ]
    );
}

#[tokio::test]
async fn register_rejects_non_https_initiate_login_uri() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    let error = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                initiate_login_uri: Some(Url::parse("http://rp.example.com/login").unwrap()),
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 25009);
    assert!(captured.lock().unwrap().is_none());
}

#[tokio::test]
async fn delete_removes_client_found_by_registration_access_token() {
    let client_oid = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
    let found_client = Arc::new(std::sync::Mutex::new(Some(registered_client(client_oid))));
    let captured = Arc::new(std::sync::Mutex::new(
        None::<OpenIdConnectClientRegistration>,
    ));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut repo = MockOpenIdConnectClientRegistrationRepository::new();
    let fc = found_client.clone();
    repo.expect_find_by_registration_access_token()
        .returning(move |_client_oid: ClientOid, _token: &str| Ok(fc.lock().unwrap().clone()));
    repo.expect_create().returning(move |_registration| {
        Ok(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
    });
    let d = deleted.clone();
    repo.expect_delete_by_oid()
        .returning(move |client_oid: ClientOid| {
            d.lock().unwrap().push(client_oid);
            Ok(())
        });
    let repo = Arc::new(repo);
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    service
        .delete(&client_oid.to_string(), "registration-token")
        .await
        .unwrap();

    assert_eq!(deleted.lock().unwrap().as_slice(), &[client_oid]);
}

#[cfg(not(feature = "allow-none-alg"))]
#[tokio::test]
async fn register_rejects_none_token_auth_method_outside_conformance() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    let error = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                token_endpoint_auth_method: Some("none".to_owned()),
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 25007);
    assert!(captured.lock().unwrap().is_none());
}

#[cfg(not(feature = "allow-none-alg"))]
#[tokio::test]
async fn register_rejects_none_id_token_signing_alg_outside_conformance() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    let error = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                id_token_signed_response_alg: Some("none".to_owned()),
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 25007);
    assert!(captured.lock().unwrap().is_none());
}

#[test]
fn sector_identifier_uris_must_include_registered_redirects() {
    let sector_redirect_uris = vec!["https://rp.example.com/allowed-callback".to_owned()];
    let redirect_uris = vec![Url::parse("https://rp.example.com/callback").unwrap()];

    assert!(
        !super::validation::sector_redirect_uris_include_registered_redirects(
            &sector_redirect_uris,
            &redirect_uris
        )
    );
}

#[cfg(feature = "allow-none-alg")]
#[tokio::test]
async fn register_allows_public_client_none_auth_in_conformance() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let deleted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repo = Arc::new(capturing_registration_repo(captured.clone(), deleted));
    let service = DynamicClientRegistrationService::new(
        Arc::new(TestRegistrationSetting(true)),
        repo.clone(),
    );

    let response = service
        .register(
            DynamicClientRegistrationRequest {
                redirect_uris: vec![Url::parse("https://rp.example.com/callback").unwrap()],
                id_token_signed_response_alg: Some("none".to_owned()),
                token_endpoint_auth_method: Some("none".to_owned()),
                ..DynamicClientRegistrationRequest::default()
            },
            &issuer(),
        )
        .await
        .unwrap();

    assert!(response.client_secret.is_none());
    assert_eq!(response.token_endpoint_auth_method.as_deref(), Some("none"));
    assert_eq!(
        response.id_token_signed_response_alg.as_deref(),
        Some("none")
    );

    let captured_val = captured.lock().unwrap().clone().unwrap();
    assert!(captured_val.client_secret.is_none());
    assert!(captured_val.metadata.settings.allow_public_client_flow);
}
