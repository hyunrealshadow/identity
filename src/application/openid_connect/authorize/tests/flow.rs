use super::fixtures::*;
use super::*;

#[tokio::test]
async fn create_authorization_request_returns_oid() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo,
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
async fn approve_authorization_request_returns_redirect_with_code_and_state() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), Uuid::new_v4(), None)
        .await
        .unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("code="));
    assert!(query.contains("state=state123"));
}

#[tokio::test]
async fn create_authorization_request_persists_login_hint() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
async fn deny_authorization_request_returns_access_denied_redirect() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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

#[test]
fn sign_implicit_id_token_includes_scope_claims() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryLoginRepository),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = User {
        oid: UserOid::from(user_oid),
        email: "alice@example.com".to_string(),
        email_normalized: "alice@example.com".to_string(),
        name: "Alice Example".to_string(),
        name_normalized: "alice example".to_string(),
        given_name: Some("Alice".to_string()),
        family_name: Some("Example".to_string()),
        middle_name: None,
        nickname: Some("alice".to_string()),
        profile: Some("users/alice".to_string()),
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
        updated_at: Some(Utc::now()),
    };
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid profile email").unwrap();

    let token = service
        .sign_implicit_id_token(
            "kid",
            std::str::from_utf8(&private_key).unwrap(),
            "RS256",
            &issuer,
            "client-1",
            &user,
            "nonce-1",
            Utc::now().timestamp(),
            None,
            None,
            &scope,
            None,
        )
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
}

#[test]
fn sign_implicit_id_token_includes_id_token_essential_claims() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryLoginRepository),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = User {
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
    };
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid").unwrap();
    let claims_request = serde_json::json!({
        "id_token": {
            "name": {"essential": true}
        }
    });

    let token = service
        .sign_implicit_id_token(
            "kid",
            std::str::from_utf8(&private_key).unwrap(),
            "RS256",
            &issuer,
            "client-1",
            &user,
            "nonce-1",
            Utc::now().timestamp(),
            None,
            None,
            &scope,
            Some(&claims_request),
        )
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(
        payload.claim("name").and_then(|v| v.as_str()),
        Some("Alice Example")
    );
    assert_eq!(payload.claim("email"), None);
}

#[test]
fn sign_implicit_id_token_omits_scope_claims_when_access_token_is_returned() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryLoginRepository),
    );
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let user = User {
        oid: UserOid::from(user_oid),
        email: "alice@example.com".to_string(),
        email_normalized: "alice@example.com".to_string(),
        name: "Alice Example".to_string(),
        name_normalized: "alice example".to_string(),
        given_name: Some("Alice".to_string()),
        family_name: Some("Example".to_string()),
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
    };
    let issuer = Url::parse("https://identity.example.com").unwrap();
    let scope = identity_domain::openid_connect::ScopeSet::parse("openid profile email").unwrap();

    let token = service
        .sign_implicit_id_token(
            "kid",
            std::str::from_utf8(&private_key).unwrap(),
            "RS256",
            &issuer,
            "client-1",
            &user,
            "nonce-1",
            Utc::now().timestamp(),
            None,
            Some("access-token"),
            &scope,
            None,
        )
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(payload.claim("email"), None);
    assert_eq!(payload.claim("name"), None);
    assert!(payload.claim("at_hash").is_some());
}
