use super::fixtures::*;
use super::*;
use crate::openid_connect::authorize::signing::SignImplicitIdTokenInput;
use crate::openid_connect::authorize::tests::fixtures::repositories::{
    ClientAuthorizationState, completed_at_for_test, insert_legacy_authorization_request_for_test,
    mock_client_auth_repo_with_state, set_stored_request_redirect_uri_for_test,
};
use crate::openid_connect::tests::fixtures::mocks::{
    MockKeyJwkRepository, MockKeyRepository, user_repo_with,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_domain::client_authorization::{ConsentState, SelectionSource};
use identity_domain::key::material::AsymmetricKeyData;
use identity_domain::openid_connect::ClaimsRequest;
use identity_domain::openid_connect::model::claim::JwtClaimNames;
use sha2::{Digest, Sha256};

type AuthorizeServiceWithRequestRepo = (AuthorizeService, Arc<ClientAuthorizationState>);

fn hybrid_user(user_oid: Uuid) -> User {
    User {
        oid: UserOid::from(user_oid),
        email: "hybrid@example.com".to_string(),
        email_normalized: "hybrid@example.com".to_string(),
        name: "Hybrid User".to_string(),
        name_normalized: "hybrid user".to_string(),
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        email_verified: true,
        phone_number: None,
        phone_number_verified: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        failed_attempts: 0,
        enabled: true,
        locked: false,
        locked_until: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn id_token_user(user_oid: Uuid) -> User {
    User {
        oid: UserOid::from(user_oid),
        email: "alice@example.com".to_string(),
        email_normalized: "alice@example.com".to_string(),
        name: "Alice Example".to_string(),
        name_normalized: "alice example".to_string(),
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        email_verified: true,
        phone_number: None,
        phone_number_verified: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        failed_attempts: 0,
        enabled: true,
        locked: false,
        locked_until: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn expected_hash_for_rs256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

fn hybrid_binding(key_oid: KeyOid, binding_oid: Uuid) -> KeyJwk {
    KeyJwk {
        oid: KeyJwkOid::from(binding_oid),
        key_oid,
        algorithm: "RS256".to_owned(),
        jwk: PublicJwk::Rsa {
            key_use: Some("sig".to_owned()),
            alg: Some("RS256".to_owned()),
            kid: Some(binding_oid.to_string()),
            n: "modulus".to_owned(),
            e: "AQAB".to_owned(),
            x5c: None,
            x5t: None,
            x5t_s256: None,
        },
        created_at: Utc::now(),
    }
}

fn default_authorize_service_with_request_repo() -> AuthorizeServiceWithRequestRepo {
    let state = Arc::new(ClientAuthorizationState::default());
    let mock_repo = Arc::new(mock_client_auth_repo_with_state(state.clone()));
    let service = AuthorizeService::new(AuthorizeServiceDependencies {
        client_repo: Arc::new(FoundClientRepository),
        credential_repo: Arc::new(empty_cred_repo()),
        client_authorization_repo: mock_repo,
        login_repo: Arc::new(mock_login_repo()),
        user_repo: Arc::new(stub_user_repo()),
        key_repo: Arc::new(stub_key_repo()),
        key_jwk_repo: Arc::new(MockKeyJwkRepository::new()),
        provider_service: provider_service(),
        signing_algorithm_detector: test_signing_algorithm_detector(),
        data_protector: test_data_protector(),
    });

    (service, state)
}

fn hybrid_key_repos(
    private_key: &[u8],
    key_oid: KeyOid,
    binding_oid: Uuid,
) -> (MockKeyRepository, MockKeyJwkRepository) {
    let key = Key {
        oid: key_oid,
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: String::new(),
            private_key: std::str::from_utf8(private_key).unwrap().to_string(),
            certificate: None,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };
    let binding = hybrid_binding(key_oid, binding_oid);

    let mut key_repo = MockKeyRepository::new();
    let k = key.clone();
    key_repo.expect_find_by_oid().returning(move |_| Ok(None));
    key_repo
        .expect_list_available_asymmetric()
        .returning(move || Ok(vec![k.clone()]));
    key_repo
        .expect_list_available_symmetric()
        .returning(|| Ok(vec![]));

    let mut jwk_repo = MockKeyJwkRepository::new();
    let b = vec![binding];
    let b2 = b.clone();
    jwk_repo
        .expect_list_active()
        .returning(move || Ok(b.clone()));
    jwk_repo
        .expect_find_active_by_key_oid_and_algorithm()
        .returning(move |oid, alg| {
            Ok(b2
                .iter()
                .find(|b| b.key_oid == oid && b.algorithm == alg)
                .cloned())
        });

    (key_repo, jwk_repo)
}

#[tokio::test]
async fn create_authorization_request_returns_oid() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    assert_ne!(oid, Uuid::nil());
}

#[tokio::test]
async fn create_login_flow_returns_protected_id() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_request_id = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let login_id = service
        .create_login_flow(request.client_id, authorization_request_id, None)
        .await
        .unwrap();

    assert!(!login_id.is_empty());
}

#[tokio::test]
async fn load_authorization_request_returns_stored_data() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let loaded = service.load_authorization_request(oid).await.unwrap();

    assert_eq!(loaded.state, "state123");
    assert_eq!(loaded.scope, "openid profile");
}

#[tokio::test]
async fn create_authorization_request_stores_wrapped_request_with_pending_interaction() {
    let (service, _) = default_authorize_service_with_request_repo();

    let mut request_params = params("openid profile");
    request_params.max_age = Some("300".to_string());

    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let stored = service
        .load_stored_authorization_request(oid)
        .await
        .unwrap();

    assert_eq!(stored.request.max_age, Some(300));
    assert_eq!(stored.interaction.consent_state, ConsentState::Pending);
    assert_eq!(stored.interaction.selection_source, None);
}

#[tokio::test]
async fn load_stored_authorization_request_supports_legacy_plain_request_rows() {
    let (service, request_repo) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = insert_legacy_authorization_request_for_test(&request_repo, &request);
    let stored = service
        .load_stored_authorization_request(oid)
        .await
        .unwrap();

    assert_eq!(stored.request.state, "state123");
    assert_eq!(stored.interaction.consent_state, ConsentState::Pending);
    assert_eq!(stored.interaction.selection_source, None);
}

#[tokio::test]
async fn record_selected_session_upgrades_auto_to_fresh_login() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    service
        .record_authorization_selection(
            authorization_oid,
            SessionOid(Uuid::new_v4()),
            Uuid::new_v4(),
            None,
            SelectionSource::Auto,
        )
        .await
        .unwrap();

    let fresh_session = SessionOid(Uuid::new_v4());
    let fresh_user = Uuid::new_v4();
    service
        .record_authorization_selection(
            authorization_oid,
            fresh_session,
            fresh_user,
            None,
            SelectionSource::FreshLogin,
        )
        .await
        .unwrap();

    let stored = service
        .load_stored_authorization_request(authorization_oid)
        .await
        .unwrap();

    assert_eq!(stored.interaction.selected_session_oid, Some(fresh_session));
    assert_eq!(
        stored.interaction.selected_user_oid.as_deref(),
        Some(fresh_user.to_string().as_str())
    );
    assert_eq!(
        stored.interaction.selection_source,
        Some(SelectionSource::FreshLogin)
    );
}

#[tokio::test]
async fn record_consent_decision_is_single_write_while_pending() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    service
        .record_consent_decision(authorization_oid, ConsentState::Approved)
        .await
        .unwrap();

    let error = service
        .record_consent_decision(authorization_oid, ConsentState::Denied)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
}

#[tokio::test]
async fn mark_authorization_request_completed_allows_only_the_first_transition() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    service
        .mark_authorization_request_completed(authorization_oid)
        .await
        .unwrap();
    let error = service
        .mark_authorization_request_completed(authorization_oid)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
}

#[tokio::test]
async fn reserve_authorization_request_terminal_allows_only_the_first_transition() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    let reservation = service
        .reserve_authorization_request_terminal(authorization_oid)
        .await
        .unwrap();
    assert!(reservation.completed_at <= Utc::now());

    let error = service
        .reserve_authorization_request_terminal(authorization_oid)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
}

#[tokio::test]
async fn deny_authorization_request_is_single_use_after_completion() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    service
        .mark_authorization_request_completed(authorization_oid)
        .await
        .unwrap();

    let error = service
        .deny_authorization_request(authorization_oid)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
}

#[tokio::test]
async fn deny_authorization_request_is_single_use_after_first_denial() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    let redirect = service
        .deny_authorization_request(authorization_oid)
        .await
        .unwrap();
    assert!(redirect.as_str().contains("error=access_denied"));

    let error = service
        .deny_authorization_request(authorization_oid)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
}

#[tokio::test]
async fn approve_authorization_request_is_single_use_after_completion() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let authorization_oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();

    service
        .mark_authorization_request_completed(authorization_oid)
        .await
        .unwrap();

    let error = service
        .approve_authorization_request(
            authorization_oid,
            SessionOid(Uuid::new_v4()),
            Uuid::new_v4(),
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
}

#[tokio::test]
async fn approve_authorization_request_returns_redirect_with_code_and_state() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), Uuid::new_v4(), None)
        .await
        .unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("code="));
    assert!(query.contains("state=state123"));
    assert!(query.contains("session_state="));
}

#[tokio::test]
async fn approve_authorization_request_failure_does_not_burn_interaction() {
    let (service, request_repo) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    set_stored_request_redirect_uri_for_test(&request_repo, oid, "not a uri");

    let error = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), Uuid::new_v4(), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), 23052);
    assert_eq!(completed_at_for_test(&request_repo, oid), None);

    set_stored_request_redirect_uri_for_test(
        &request_repo,
        oid,
        "https://client.example.com/callback",
    );

    let redirect = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), Uuid::new_v4(), None)
        .await
        .unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("code="));
    assert!(query.contains("state=state123"));
    assert!(completed_at_for_test(&request_repo, oid).is_some());
}

#[tokio::test]
async fn approve_code_id_token_hybrid_returns_fragment_with_code_and_id_token_hash() {
    let request_repo = Arc::new(mock_client_auth_repo_with_state(Arc::new(
        ClientAuthorizationState::default(),
    )));
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let binding_oid = Uuid::new_v4();
    let service = {
        let (key_repo, jwk_repo) = hybrid_key_repos(&private_key, key_oid, binding_oid);
        AuthorizeService::new(AuthorizeServiceDependencies {
            client_repo: Arc::new(FoundClientRepository),
            credential_repo: Arc::new(empty_cred_repo()),
            client_authorization_repo: request_repo,
            login_repo: Arc::new(mock_login_repo()),
            user_repo: Arc::new(user_repo_with(hybrid_user(user_oid))),
            key_repo: Arc::new(key_repo),
            key_jwk_repo: Arc::new(jwk_repo),
            provider_service: provider_service(),
            signing_algorithm_detector: test_signing_algorithm_detector(),
            data_protector: test_data_protector(),
        })
    };

    let mut request_params = params("openid profile");
    request_params.response_type = "code id_token".to_string();
    request_params.nonce = Some("nonce-hybrid".to_string());
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), user_oid, None)
        .await
        .unwrap();

    assert_eq!(redirect.query(), None);
    let fragment = redirect.fragment().unwrap();
    let pairs = url::form_urlencoded::parse(fragment.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<std::collections::HashMap<_, _>>();
    let code = pairs.get("code").unwrap();
    let id_token = pairs.get("id_token").unwrap();
    assert_eq!(pairs.get("state").map(String::as_str), Some("state123"));
    assert!(pairs.contains_key("session_state"));
    assert!(!code.is_empty());

    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let header = jwt::decode_header(id_token).unwrap();
    let (payload, _) = jwt::decode_with_verifier(id_token, &verifier).unwrap();
    assert_eq!(
        header
            .claim(JwtClaimNames::KID)
            .and_then(|value| value.as_str()),
        Some(binding_oid.to_string().as_str())
    );
    assert_eq!(
        payload.claim(JwtClaimNames::NONCE).and_then(|v| v.as_str()),
        Some("nonce-hybrid")
    );
    assert_eq!(
        payload.claim(JwtClaimNames::C_HASH).unwrap(),
        &serde_json::json!(expected_hash_for_rs256(code))
    );
}

#[tokio::test]
async fn approve_implicit_flow_returns_session_state() {
    let request_repo = Arc::new(mock_client_auth_repo_with_state(Arc::new(
        ClientAuthorizationState::default(),
    )));
    let (private_key, _public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let service = {
        let binding_oid = Uuid::new_v4();
        let (key_repo, jwk_repo) = hybrid_key_repos(&private_key, key_oid, binding_oid);
        AuthorizeService::new(AuthorizeServiceDependencies {
            client_repo: Arc::new(FoundClientRepository),
            credential_repo: Arc::new(empty_cred_repo()),
            client_authorization_repo: request_repo,
            login_repo: Arc::new(mock_login_repo()),
            user_repo: Arc::new(user_repo_with(hybrid_user(user_oid))),
            key_repo: Arc::new(key_repo),
            key_jwk_repo: Arc::new(jwk_repo),
            provider_service: provider_service(),
            signing_algorithm_detector: test_signing_algorithm_detector(),
            data_protector: test_data_protector(),
        })
    };

    let mut request_params = params("openid profile");
    request_params.response_type = "id_token".to_string();
    request_params.nonce = Some("nonce-implicit".to_string());
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), user_oid, None)
        .await
        .unwrap();

    let fragment = redirect.fragment().unwrap();
    let pairs = url::form_urlencoded::parse(fragment.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<std::collections::HashMap<_, _>>();

    assert!(pairs.contains_key("id_token"));
    assert_eq!(pairs.get("state").map(String::as_str), Some("state123"));
    assert!(pairs.contains_key("session_state"));
}

#[tokio::test]
async fn approve_code_id_token_token_hybrid_returns_code_tokens_and_hashes() {
    let request_repo = Arc::new(mock_client_auth_repo_with_state(Arc::new(
        ClientAuthorizationState::default(),
    )));
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let service = {
        let binding_oid = Uuid::new_v4();
        let (key_repo, jwk_repo) = hybrid_key_repos(&private_key, key_oid, binding_oid);
        AuthorizeService::new(AuthorizeServiceDependencies {
            client_repo: Arc::new(FoundClientRepository),
            credential_repo: Arc::new(empty_cred_repo()),
            client_authorization_repo: request_repo,
            login_repo: Arc::new(mock_login_repo()),
            user_repo: Arc::new(user_repo_with(hybrid_user(user_oid))),
            key_repo: Arc::new(key_repo),
            key_jwk_repo: Arc::new(jwk_repo),
            provider_service: provider_service(),
            signing_algorithm_detector: test_signing_algorithm_detector(),
            data_protector: test_data_protector(),
        })
    };

    let mut request_params = params("openid profile");
    request_params.response_type = "code id_token token".to_string();
    request_params.nonce = Some("nonce-hybrid".to_string());
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), user_oid, None)
        .await
        .unwrap();

    let fragment = redirect.fragment().unwrap();
    let pairs = url::form_urlencoded::parse(fragment.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<std::collections::HashMap<_, _>>();
    let code = pairs.get("code").unwrap();
    let access_token = pairs.get("access_token").unwrap();
    let id_token = pairs.get("id_token").unwrap();
    assert_eq!(pairs.get("token_type").map(String::as_str), Some("Bearer"));
    assert_eq!(pairs.get("expires_in").map(String::as_str), Some("3600"));
    assert_eq!(
        pairs.get("scope").map(String::as_str),
        Some("openid profile")
    );

    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(id_token, &verifier).unwrap();
    assert_eq!(
        payload.claim(JwtClaimNames::C_HASH).unwrap(),
        &serde_json::json!(expected_hash_for_rs256(code))
    );
    assert_eq!(
        payload.claim(JwtClaimNames::AT_HASH).unwrap(),
        &serde_json::json!(expected_hash_for_rs256(access_token))
    );
}

#[tokio::test]
async fn approve_code_token_hybrid_returns_code_and_access_token_without_nonce() {
    let request_repo = Arc::new(mock_client_auth_repo_with_state(Arc::new(
        ClientAuthorizationState::default(),
    )));
    let (private_key, _public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let service = {
        let binding_oid = Uuid::new_v4();
        let (key_repo, jwk_repo) = hybrid_key_repos(&private_key, key_oid, binding_oid);
        AuthorizeService::new(AuthorizeServiceDependencies {
            client_repo: Arc::new(FoundClientRepository),
            credential_repo: Arc::new(empty_cred_repo()),
            client_authorization_repo: request_repo,
            login_repo: Arc::new(mock_login_repo()),
            user_repo: Arc::new(user_repo_with(hybrid_user(user_oid))),
            key_repo: Arc::new(key_repo),
            key_jwk_repo: Arc::new(jwk_repo),
            provider_service: provider_service(),
            signing_algorithm_detector: test_signing_algorithm_detector(),
            data_protector: test_data_protector(),
        })
    };

    let mut request_params = params("openid profile");
    request_params.response_type = "code token".to_string();
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, SessionOid(Uuid::new_v4()), user_oid, None)
        .await
        .unwrap();

    let fragment = redirect.fragment().unwrap();
    let pairs = url::form_urlencoded::parse(fragment.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<std::collections::HashMap<_, _>>();

    assert!(pairs.contains_key("code"));
    assert!(pairs.contains_key("access_token"));
    assert!(!pairs.contains_key("id_token"));
    assert_eq!(pairs.get("token_type").map(String::as_str), Some("Bearer"));
    assert_eq!(pairs.get("state").map(String::as_str), Some("state123"));
}

#[tokio::test]
async fn create_authorization_request_persists_login_hint() {
    let (service, _) = default_authorize_service_with_request_repo();

    let mut request_params = params("openid profile");
    request_params.login_hint = Some("alice@example.com".to_string());

    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let loaded = service.load_authorization_request(oid).await.unwrap();

    assert_eq!(loaded.login_hint.as_deref(), Some("alice@example.com"));
}

#[tokio::test]
async fn create_authorization_request_persists_prompt() {
    let (service, _) = default_authorize_service_with_request_repo();

    let mut request_params = params("openid profile");
    request_params.prompt = Some("consent login".to_string());

    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let loaded = service.load_authorization_request(oid).await.unwrap();

    assert_eq!(loaded.prompt.as_deref(), Some("consent login"));
}

#[tokio::test]
async fn deny_authorization_request_returns_access_denied_redirect() {
    let (service, _) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service.deny_authorization_request(oid).await.unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("error=access_denied"));
    assert!(query.contains("state=state123"));
}

#[tokio::test]
async fn deny_authorization_request_failure_does_not_burn_interaction() {
    let (service, request_repo) = default_authorize_service_with_request_repo();

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    set_stored_request_redirect_uri_for_test(&request_repo, oid, "not a uri");

    let error = service.deny_authorization_request(oid).await.unwrap_err();
    assert_eq!(error.code(), 23052);
    assert_eq!(completed_at_for_test(&request_repo, oid), None);

    set_stored_request_redirect_uri_for_test(
        &request_repo,
        oid,
        "https://client.example.com/callback",
    );

    let redirect = service.deny_authorization_request(oid).await.unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("error=access_denied"));
    assert!(query.contains("state=state123"));
    assert!(completed_at_for_test(&request_repo, oid).is_some());
}

#[test]
fn sign_implicit_id_token_includes_scope_claims() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = User {
        given_name: Some("Alice".to_string()),
        family_name: Some("Example".to_string()),
        nickname: Some("alice".to_string()),
        profile: Some("users/alice".to_string()),
        updated_at: Some(Utc::now()),
        ..id_token_user(user_oid)
    };
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid profile email").unwrap();

    let token = service
        .sign_implicit_id_token(SignImplicitIdTokenInput {
            key_id: "kid",
            private_key_pem: std::str::from_utf8(&private_key).unwrap(),
            alg: "RS256",
            issuer: &issuer,
            audience: "client-1",
            user: &user,
            nonce: "nonce-1",
            auth_time: Utc::now().timestamp(),
            acr: None,
            access_token: None,
            code: None,
            protected_session_id: None,
            scope: &scope,
            claims_request: None,
        })
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(
        payload.claim("name").and_then(|v| v.as_str()),
        Some("Alice Example")
    );
    assert_eq!(
        payload.claim("email").and_then(|v| v.as_str()),
        Some("alice@example.com")
    );
    assert_eq!(
        payload.claim("given_name").and_then(|v| v.as_str()),
        Some("Alice")
    );
    assert_eq!(
        payload.claim(JwtClaimNames::AZP).unwrap(),
        &serde_json::json!("client-1")
    );
    assert_eq!(
        payload.claim(JwtClaimNames::AMR).unwrap(),
        &serde_json::json!(["pwd"])
    );
}

#[test]
fn sign_implicit_id_token_includes_id_token_essential_claims() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = id_token_user(user_oid);
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid").unwrap();
    let claims_request: ClaimsRequest = serde_json::from_value(serde_json::json!({
        "id_token": {
            "name": {"essential": true}
        }
    }))
    .unwrap();

    let token = service
        .sign_implicit_id_token(SignImplicitIdTokenInput {
            key_id: "kid",
            private_key_pem: std::str::from_utf8(&private_key).unwrap(),
            alg: "RS256",
            issuer: &issuer,
            audience: "client-1",
            user: &user,
            nonce: "nonce-1",
            auth_time: Utc::now().timestamp(),
            acr: None,
            access_token: None,
            code: None,
            protected_session_id: Some("protected-session"),
            scope: &scope,
            claims_request: Some(&claims_request),
        })
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(
        payload.claim("name").and_then(|v| v.as_str()),
        Some("Alice Example")
    );
    assert_eq!(
        payload.claim(JwtClaimNames::SID).unwrap(),
        &serde_json::json!("protected-session")
    );
    assert_eq!(payload.claim("email"), None);
}

#[test]
fn sign_implicit_id_token_omits_scope_claims_when_access_token_is_returned() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = id_token_user(user_oid);
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid profile email").unwrap();

    let token = service
        .sign_implicit_id_token(SignImplicitIdTokenInput {
            key_id: "kid",
            private_key_pem: std::str::from_utf8(&private_key).unwrap(),
            alg: "RS256",
            issuer: &issuer,
            audience: "client-1",
            user: &user,
            nonce: "nonce-1",
            auth_time: Utc::now().timestamp(),
            acr: None,
            access_token: Some("access-token"),
            code: None,
            protected_session_id: None,
            scope: &scope,
            claims_request: None,
        })
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(payload.claim("email"), None);
    assert_eq!(payload.claim("name"), None);
    assert!(payload.claim("at_hash").is_some());
}

#[test]
fn sign_implicit_id_token_omits_scope_claims_when_code_is_returned() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(empty_cred_repo()),
        Arc::new(mock_login_repo()),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = id_token_user(user_oid);
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid profile email").unwrap();

    let token = service
        .sign_implicit_id_token(SignImplicitIdTokenInput {
            key_id: "kid",
            private_key_pem: std::str::from_utf8(&private_key).unwrap(),
            alg: "RS256",
            issuer: &issuer,
            audience: "client-1",
            user: &user,
            nonce: "nonce-1",
            auth_time: Utc::now().timestamp(),
            acr: None,
            access_token: None,
            code: Some("authorization-code"),
            protected_session_id: None,
            scope: &scope,
            claims_request: None,
        })
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(payload.claim("email"), None);
    assert_eq!(payload.claim("name"), None);
    assert!(payload.claim("c_hash").is_some());
}
