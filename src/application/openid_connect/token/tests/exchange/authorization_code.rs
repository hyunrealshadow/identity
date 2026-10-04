use crate::key::asymmetric::AsymmetricKeyService;
use crate::openid_connect::token::signing::{SignAccessTokenInput, SignIdTokenInput};
use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;
use identity_domain::auth::ACR_AAL1;
use identity_domain::auth::SessionOid;
use identity_domain::key::{KeyJwk, KeyJwkOid, PublicJwk};

fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn expired_authorization_code_has_a_distinct_error() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, _) = rs256_token_service_with_public_key(repo.clone(), user_oid);
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid".to_owned(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec![],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .unwrap();
    let error = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_owned()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), 24053);
    assert!(
        repo.find_by_oid(record.oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
}

fn rs256_token_service_with_public_key(
    repo: Arc<MockClientAuthorizationRepository>,
    user_oid: Uuid,
) -> (TokenService, Vec<u8>) {
    let key = key_for_algorithm("RS256");
    let public_key = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.as_bytes().to_vec(),
        KeyData::Symmetric(_) => unreachable!("test signing key must be asymmetric"),
    };
    let service = build_token_service_with_key(repo, key, user_oid);

    (service, public_key)
}

#[tokio::test]
async fn oauth20_client_may_omit_token_redirect_when_authorization_omitted_it() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "profile".to_owned(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec![],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                redirect_uri_was_supplied: false,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
    let service =
        build_token_service_with_client_repo(repo, user_oid, Arc::new(InMemoryClientRepository));

    assert!(
        service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                resources: Vec::new(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: None,
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
                code_verifier: None,
            })
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn oidc10_single_redirect_client_may_omit_token_redirect() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid profile".to_owned(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec![],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
    let service =
        build_token_service_with_client_repo(repo, user_oid, Arc::new(InMemoryClientRepository));

    assert!(
        service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                resources: Vec::new(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: None,
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
                code_verifier: None,
            })
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn exchange_authorization_code_revokes_code_after_success() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, public_key) = rs256_token_service_with_public_key(repo.clone(), user_oid);

    let session_oid = Uuid::new_v4();
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid profile".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some(s256_challenge("verifier-123")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(session_oid),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let code = STANDARD.encode(record.oid.as_bytes());
    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code,
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-123".to_string()),
        })
        .await
        .unwrap();

    assert!(matches!(
        result.token_type,
        crate::openid_connect::token::TokenType::Bearer
    ));
    assert!(result.id_token.is_some());
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (access_payload, _) = jwt::decode_with_verifier(&result.access_token, &verifier).unwrap();
    let (id_payload, _) =
        jwt::decode_with_verifier(result.id_token.as_ref().unwrap(), &verifier).unwrap();
    assert_eq!(access_payload.subject().unwrap(), user_oid.to_string());
    assert_eq!(id_payload.subject().unwrap(), user_oid.to_string());
    assert_eq!(
        id_payload.claim(JwtClaimNames::NONCE).unwrap(),
        &serde_json::json!("nonce-123")
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::AT_HASH).unwrap(),
        &serde_json::json!(expected_at_hash(&result.access_token))
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::AZP).unwrap(),
        &serde_json::json!(Uuid::nil().to_string())
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::AMR).unwrap(),
        &serde_json::json!(["pwd"])
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::SID),
        access_payload.claim(JwtClaimNames::SID)
    );
    assert_ne!(
        id_payload.claim(JwtClaimNames::SID).unwrap(),
        &serde_json::json!(session_oid.to_string())
    );
    assert!(
        repo.find_by_oid(record.oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
}

#[tokio::test]
async fn exchange_authorization_code_without_openid_issues_no_id_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, _) = rs256_token_service_with_public_key(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "profile".to_string(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
        })
        .await
        .unwrap();

    assert_eq!(result.scope, "profile");
    assert!(
        result.id_token.is_none(),
        "an authorization that never requested openid gets no ID token"
    );
}

#[tokio::test]
async fn exchange_authorization_code_keeps_email_scope_claims_out_of_id_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, public_key) = rs256_token_service_with_public_key(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "email openid".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some(s256_challenge("verifier-123")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: Some(ACR_AAL1.to_string()),
                amr: vec!["pwd".to_owned()],
                auth_time: Some(chrono::Utc::now().timestamp()),
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-123".to_string()),
        })
        .await
        .unwrap();

    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (id_payload, _) =
        jwt::decode_with_verifier(result.id_token.as_ref().unwrap(), &verifier).unwrap();

    assert!(id_payload.claim(JwtClaimNames::EMAIL).is_none());
    assert!(id_payload.claim(JwtClaimNames::EMAIL_VERIFIED).is_none());
}

#[tokio::test]
async fn scoped_claims_client_includes_profile_email_claims_in_code_flow_id_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, public_key) = build_token_service_with_scoped_claims(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid profile email".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some(s256_challenge("verifier-123")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-123".to_string()),
        })
        .await
        .unwrap();

    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (id_payload, _) =
        jwt::decode_with_verifier(result.id_token.as_ref().unwrap(), &verifier).unwrap();
    let (access_payload, _) = jwt::decode_with_verifier(&result.access_token, &verifier).unwrap();
    assert!(access_payload.claim(JwtClaimNames::NAME).is_none());
    assert!(access_payload.claim(JwtClaimNames::EMAIL).is_none());

    // profile + email scope → scoped standard claims present (scope-driven, no
    // claims_request needed). sub stays the raw user oid (public subject type).
    assert_eq!(id_payload.subject().unwrap(), user_oid.to_string());
    assert_eq!(
        id_payload.claim(JwtClaimNames::NAME).unwrap(),
        &serde_json::json!("Alg User")
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::EMAIL).unwrap(),
        &serde_json::json!("alg@example.com")
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::EMAIL_VERIFIED).unwrap(),
        &serde_json::json!(true)
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::PREFERRED_USERNAME).unwrap(),
        &serde_json::json!("Alg User")
    );
}

#[tokio::test]
async fn scoped_claims_client_omits_claims_outside_granted_scope_in_code_flow_id_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, public_key) = build_token_service_with_scoped_claims(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some(s256_challenge("verifier-123")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-123".to_string()),
        })
        .await
        .unwrap();

    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (id_payload, _) =
        jwt::decode_with_verifier(result.id_token.as_ref().unwrap(), &verifier).unwrap();

    assert!(id_payload.claim(JwtClaimNames::NAME).is_none());
    assert!(id_payload.claim(JwtClaimNames::EMAIL).is_none());
    assert!(id_payload.claim(JwtClaimNames::EMAIL_VERIFIED).is_none());
}

#[tokio::test]
async fn exchange_authorization_code_rejects_invalid_pkce_verifier() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid profile".to_string(),
                nonce: None,
                code_challenge: Some(s256_challenge("expected-verifier")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let code = STANDARD.encode(record.oid.as_bytes());
    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code,
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("wrong-verifier".to_string()),
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn exchange_authorization_code_rejects_reused_code() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let key = key_for_algorithm("RS256");
    let public_key = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.as_bytes().to_vec(),
        KeyData::Symmetric(_) => unreachable!("test signing key must be asymmetric"),
    };
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());
    let key_repo = Arc::new(key_repo_with_keys(vec![key.clone()]));
    let user = test_user(user_oid);
    let service = TokenService::new(TokenServiceDependencies {
        device_repo: Arc::new(
            crate::openid_connect::tests::fixtures::mocks::MockDeviceAuthorizationRepository::new(),
        ),
        client_authorization_repo: repo.clone(),
        key_repo: key_repo.clone(),
        key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![binding])),
        user_repo: Arc::new(InMemoryUserRepository { user: user.clone() }),
        client_repo: Arc::new(InMemoryClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            r#type: OpenIdConnectCredentialType::ClientSecret,
            hint: "token".to_string(),
            data: OpenIdConnectCredentialData::ClientSecret {
                secret: "secret-123".to_string(),
            },
            expires_at: Utc::now() + chrono::Duration::days(1),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }])),
        provider_service: provider_service(),
        signing_algorithm_detector: signing_algorithm_detector(),
        data_protector: InMemoryDataProtector::new(),
    });

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid profile".to_string(),
                nonce: None,
                code_challenge: Some(s256_challenge("verifier-789")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let code = STANDARD.encode(record.oid.as_bytes());
    let first_response = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: code.clone(),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-789".to_string()),
        })
        .await
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (access_payload, _) =
        jwt::decode_with_verifier(&first_response.access_token, &verifier).unwrap();
    let access_token_jti = access_payload.jwt_id().unwrap().to_string();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code,
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-789".to_string()),
        })
        .await;

    assert_eq!(result.unwrap_err().code(), 24052);
    assert!(
        repo.find_by_oid(Uuid::parse_str(&access_token_jti).unwrap())
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    let user_info_service = crate::openid_connect::user_info::UserInfoService::new(
        Arc::new(InMemoryUserRepository { user }),
        Arc::new(InMemoryClientRepository),
        Arc::new(cred_repo_with(vec![])),
        repo.clone(),
        Arc::new(AsymmetricKeyService::new(
            key_repo,
            Arc::new(TestAsymmetricKeyGenerator),
            test_key_jwk_generator(),
            None,
        )),
        provider_service(),
    );
    assert!(
        user_info_service
            .validate_access_token(&first_response.access_token)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn exchange_authorization_code_returns_refresh_token_for_offline_access() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-offline".to_string()),
                code_challenge: Some(s256_challenge("verifier-offline")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-offline".to_string()),
        })
        .await
        .unwrap();

    assert!(result.refresh_token.is_some());
    let refresh_token_oid = Uuid::from_slice(
        &STANDARD
            .decode(result.refresh_token.as_ref().unwrap())
            .unwrap(),
    )
    .unwrap();
    let stored = repo.find_by_oid(refresh_token_oid).await.unwrap();
    assert_eq!(
        stored.as_ref().map(|record| &record.type_),
        Some(&ClientAuthorizationType::RefreshToken)
    );
}

#[tokio::test]
async fn exchange_authorization_code_signs_and_validates_supported_default_algs() {
    for alg in [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "ES256K",
        "EdDSA",
    ] {
        let repo = Arc::new(mock_client_auth_repo());
        let user_oid = Uuid::new_v4();
        let key = key_for_algorithm(alg);
        let public_key = match &key.data {
            KeyData::Asymmetric(data) => data.public_key.clone(),
            KeyData::Symmetric(_) => unreachable!(),
        };
        let service = build_token_service_with_key(repo.clone(), key.clone(), user_oid);

        let record = repo
            .create(
                Uuid::nil(),
                ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                    resources: Vec::new(),
                    scope: "openid profile".to_string(),
                    nonce: Some(format!("nonce-{alg}")),
                    code_challenge: Some(s256_challenge(&format!("verifier-{alg}"))),
                    code_challenge_method: Some("S256".parse().unwrap()),
                    user_oid: user_oid.to_string(),
                    session_oid: SessionOid::from(Uuid::new_v4()),
                    protected_session_id: None,
                    acr: None,
                    amr: vec!["pwd".to_owned()],
                    auth_time: None,
                    redirect_uri: "https://client.example.com/callback".to_string(),
                    redirect_uri_was_supplied: true,
                    claims: None,
                }),
                Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .unwrap();

        let result = service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                resources: Vec::new(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: Some("https://client.example.com/callback".to_string()),
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_string()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
                code_verifier: Some(format!("verifier-{alg}")),
            })
            .await
            .unwrap();

        let access_payload = decode_jwt_with_alg(&result.access_token, &public_key, alg);
        let id_payload = decode_jwt_with_alg(result.id_token.as_ref().unwrap(), &public_key, alg);
        assert_eq!(access_payload.subject().unwrap(), user_oid.to_string());
        assert_eq!(id_payload.subject().unwrap(), user_oid.to_string());
        assert_eq!(
            id_payload.claim(JwtClaimNames::AT_HASH).unwrap(),
            &serde_json::json!(expected_at_hash_for_alg(&result.access_token, alg))
        );

        user_info_service_with_key(repo.clone(), key, user_oid)
            .validate_access_token(&result.access_token)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn exchange_authorization_code_uses_key_jwk_oid_for_signed_token_headers() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let key = key_for_algorithm("RS256");
    let binding_oid = Uuid::new_v4();
    let binding = KeyJwk {
        oid: KeyJwkOid::from(binding_oid),
        key_oid: key.oid,
        algorithm: "RS256".parse().unwrap(),
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
    };
    let public_key = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.clone(),
        KeyData::Symmetric(_) => unreachable!(),
    };

    let service = TokenService::new(TokenServiceDependencies {
        device_repo: Arc::new(
            crate::openid_connect::tests::fixtures::mocks::MockDeviceAuthorizationRepository::new(),
        ),
        client_authorization_repo: repo.clone(),
        key_repo: Arc::new(key_repo_with_keys(vec![key.clone()])),
        key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![binding])),
        user_repo: Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
        }),
        client_repo: Arc::new(InMemoryClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            r#type: OpenIdConnectCredentialType::ClientSecret,
            hint: "token".to_string(),
            data: OpenIdConnectCredentialData::ClientSecret {
                secret: "secret-123".to_string(),
            },
            expires_at: Utc::now() + chrono::Duration::days(1),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }])),
        provider_service: provider_service(),
        signing_algorithm_detector: signing_algorithm_detector(),
        data_protector: InMemoryDataProtector::new(),
    });

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid profile".to_string(),
                nonce: Some("nonce-rs256".to_string()),
                code_challenge: Some(s256_challenge("verifier-rs256")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-rs256".to_string()),
        })
        .await
        .unwrap();

    let access_header = jwt::decode_header(&result.access_token).unwrap();
    let id_header = jwt::decode_header(result.id_token.as_ref().unwrap()).unwrap();
    let verifier = RS256.verifier_from_pem(public_key.as_bytes()).unwrap();
    let _ = jwt::decode_with_verifier(&result.access_token, &verifier).unwrap();
    let _ = jwt::decode_with_verifier(result.id_token.as_ref().unwrap(), &verifier).unwrap();

    assert_eq!(
        access_header
            .claim(JwtClaimNames::KID)
            .and_then(|value| value.as_str()),
        Some(binding_oid.to_string().as_str())
    );
    assert_eq!(
        id_header
            .claim(JwtClaimNames::KID)
            .and_then(|value| value.as_str()),
        Some(binding_oid.to_string().as_str())
    );
}

#[tokio::test]
async fn authorization_and_refresh_use_client_algorithm_for_access_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let default_ec_key = key_for_algorithm("ES256");
    let requested_rsa_key = key_for_algorithm("RS256");
    let ec_binding = key_jwk_binding(&default_ec_key, "ES256", Uuid::new_v4());
    let rsa_binding = key_jwk_binding(&requested_rsa_key, "RS256", Uuid::new_v4());
    let rsa_public_key = match &requested_rsa_key.data {
        KeyData::Asymmetric(data) => data.public_key.clone(),
        KeyData::Symmetric(_) => unreachable!(),
    };
    let mut service = build_token_service_with_client_repo(
        repo.clone(),
        user_oid,
        Arc::new(IdTokenAlgorithmClientRepository {
            algorithm: JwaSigningAlgorithm::Rs256,
        }),
    );
    service.key_repo = Arc::new(key_repo_with_keys(vec![default_ec_key, requested_rsa_key]));
    service.key_jwk_repo = Arc::new(jwk_repo_with_bindings(vec![
        ec_binding,
        rsa_binding.clone(),
    ]));

    let expected_kid = Uuid::from(rsa_binding.oid).to_string();
    for scope in ["openid offline_access profile", "offline_access profile"] {
        let has_openid = scope.split_whitespace().any(|value| value == "openid");
        let record = repo
            .create(
                Uuid::nil(),
                ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                    resources: Vec::new(),
                    scope: scope.to_owned(),
                    nonce: has_openid.then_some("nonce-rsa".to_owned()),
                    code_challenge: Some(s256_challenge("verifier-rsa")),
                    code_challenge_method: Some("S256".parse().unwrap()),
                    user_oid: user_oid.to_string(),
                    session_oid: SessionOid::from(Uuid::new_v4()),
                    protected_session_id: None,
                    acr: None,
                    amr: vec!["pwd".to_owned()],
                    auth_time: None,
                    redirect_uri: "https://client.example.com/callback".to_owned(),
                    redirect_uri_was_supplied: true,
                    claims: None,
                }),
                Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .unwrap();

        let issued = service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                resources: Vec::new(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: Some("https://client.example.com/callback".to_owned()),
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
                code_verifier: Some("verifier-rsa".to_owned()),
            })
            .await
            .unwrap();
        let refreshed = service
            .exchange_refresh_token(RefreshTokenGrantParams {
                resources: Vec::new(),
                scope: None,
                refresh_token: issued.refresh_token.clone().unwrap(),
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
            })
            .await
            .unwrap();

        for tokens in [&issued, &refreshed] {
            assert_eq!(tokens.id_token.is_some(), has_openid);
            for token in std::iter::once(&tokens.access_token).chain(tokens.id_token.iter()) {
                let header = jwt::decode_header(token).unwrap();
                assert_eq!(
                    header.claim(JwtClaimNames::ALG).and_then(|v| v.as_str()),
                    Some("RS256")
                );
                assert_eq!(
                    header.claim(JwtClaimNames::KID).and_then(|v| v.as_str()),
                    Some(expected_kid.as_str())
                );
                decode_jwt_with_alg(token, &rsa_public_key, "RS256");
            }
        }
    }
}

#[tokio::test]
async fn scoped_user_claims_in_access_token_are_opt_in_for_code_and_refresh() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service_with_client_repo(
        repo.clone(),
        user_oid,
        Arc::new(AccessClaimsClientRepository),
    );

    for scope in [
        "openid profile email offline_access",
        "profile email offline_access",
        "openid profile offline_access",
    ] {
        let has_openid = scope.split_whitespace().any(|value| value == "openid");
        let has_email = scope.split_whitespace().any(|value| value == "email");
        let record = repo
            .create(
                Uuid::nil(),
                ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                    resources: Vec::new(),
                    scope: scope.to_owned(),
                    nonce: has_openid.then_some("nonce-claims".to_owned()),
                    code_challenge: Some(s256_challenge("verifier-claims")),
                    code_challenge_method: Some("S256".parse().unwrap()),
                    user_oid: user_oid.to_string(),
                    session_oid: SessionOid::from(Uuid::new_v4()),
                    protected_session_id: None,
                    acr: None,
                    amr: vec!["pwd".to_owned()],
                    auth_time: None,
                    redirect_uri: "https://client.example.com/callback".to_owned(),
                    redirect_uri_was_supplied: true,
                    claims: None,
                }),
                Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .unwrap();
        let issued = service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                resources: Vec::new(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: Some("https://client.example.com/callback".to_owned()),
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
                code_verifier: Some("verifier-claims".to_owned()),
            })
            .await
            .unwrap();
        let refreshed = service
            .exchange_refresh_token(RefreshTokenGrantParams {
                resources: Vec::new(),
                scope: None,
                refresh_token: issued.refresh_token.clone().unwrap(),
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
            })
            .await
            .unwrap();

        for tokens in [&issued, &refreshed] {
            let access_claims = serde_json::from_slice::<serde_json::Value>(
                &URL_SAFE_NO_PAD
                    .decode(tokens.access_token.split('.').nth(1).unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(access_claims["sub"], user_oid.to_string());
            assert_eq!(access_claims["name"], "A");
            if has_email {
                assert_eq!(access_claims["email"], "a@example.com");
                assert_eq!(access_claims["email_verified"], true);
            } else {
                assert!(access_claims.get("email").is_none());
                assert!(access_claims.get("email_verified").is_none());
            }
            assert_eq!(tokens.id_token.is_some(), has_openid);
            if let Some(id_token) = &tokens.id_token {
                let id_claims = serde_json::from_slice::<serde_json::Value>(
                    &URL_SAFE_NO_PAD
                        .decode(id_token.split('.').nth(1).unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert!(id_claims.get("name").is_none());
                assert!(id_claims.get("email").is_none());
            }
        }
    }
}

#[tokio::test]
async fn ps_algorithms_sign_tokens_and_validate_userinfo() {
    for alg in ["PS256", "PS384", "PS512"] {
        let repo = Arc::new(mock_client_auth_repo());
        let user_oid = Uuid::new_v4();
        let key = key_for_algorithm(alg);
        let (key_id, private_key, public_key) = match &key.data {
            KeyData::Asymmetric(data) => (
                Uuid::from(key.oid).to_string(),
                data.private_key.clone(),
                data.public_key.clone(),
            ),
            KeyData::Symmetric(_) => unreachable!(),
        };
        let service = build_token_service_with_key(repo.clone(), key.clone(), user_oid);
        let issuer = provider_service().issuer().unwrap();
        let access_record = service
            .client_authorization_repo
            .create(
                Uuid::nil(),
                ClientAuthorizationData::AccessToken(identity_domain::client_authorization::AccessTokenData {
                    scope: "openid profile".to_owned(),
                    user_oid: user_oid.to_string(),
                    session_oid: Some(SessionOid::from(Uuid::new_v4())),
                    protected_session_id: None,
                    authorization_code_oid: None,
                    refresh_token_oid: None,
                    device_authorization_oid: None,
                    client_authentication_mode: Some(identity_domain::client_authorization::ClientAuthenticationMode::Confidential),
                }),
                Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        let client = service
            .client_repo
            .find_by_oid(Uuid::nil())
            .await
            .unwrap()
            .unwrap();
        let user = test_user(user_oid);
        let access_token = service
            .sign_access_token(SignAccessTokenInput {
                resources: &[],
                token_id: &access_record.oid.to_string(),
                key_id: &key_id,
                private_key_pem: &private_key,
                alg: alg.parse().unwrap(),
                issuer: &issuer,
                audience: &Uuid::nil().to_string(),
                client_id: &Uuid::nil().to_string(),
                user_oid: &user_oid,
                client: &client,
                user: Some(&user),
                protected_session_id: Some(&Uuid::new_v4().to_string()),
                scope: "openid profile",
                claims: None,
                auth_time: None,
                acr: None,
                amr: &["pwd".to_owned()],
            })
            .await
            .unwrap();
        let id_token = service
            .sign_id_token(SignIdTokenInput {
                key_id: &key_id,
                private_key_pem: &private_key,
                alg: alg.parse().unwrap(),
                issuer: &issuer,
                audience: &Uuid::nil().to_string(),
                client: &client,
                user: &user,
                scope: "openid profile",
                nonce: None,
                auth_time: None,
                acr: None,
                amr: &["pwd".to_owned()],
                access_token: Some(&access_token),
                protected_session_id: None,
            })
            .await
            .unwrap();

        let access_payload = decode_jwt_with_alg(&access_token, &public_key, alg);
        let id_payload = decode_jwt_with_alg(&id_token, &public_key, alg);
        assert_eq!(access_payload.subject().unwrap(), user_oid.to_string());
        assert_eq!(
            access_payload.claim(JwtClaimNames::AMR).unwrap(),
            &serde_json::json!(["pwd"])
        );
        assert_eq!(
            id_payload.claim(JwtClaimNames::AMR).unwrap(),
            &serde_json::json!(["pwd"])
        );
        assert_eq!(
            id_payload.claim(JwtClaimNames::AT_HASH).unwrap(),
            &serde_json::json!(expected_at_hash_for_alg(&access_token, alg))
        );

        user_info_service_with_key(repo.clone(), key, user_oid)
            .validate_access_token(&access_token)
            .await
            .unwrap();
    }
}

use super::RecordingSink;

#[tokio::test]
async fn successful_exchange_emits_consumption_and_issuance_events() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, _) = rs256_token_service_with_public_key(repo.clone(), user_oid);
    let sink = Arc::new(RecordingSink::default());
    let service = service.with_events(sink.clone());

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: Vec::new(),
                scope: "openid".to_owned(),
                nonce: None,
                code_challenge: Some(s256_challenge("verifier-123")),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec![],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                redirect_uri_was_supplied: true,
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_owned()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-123".to_owned()),
        })
        .await
        .unwrap();

    let names = sink.names();
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "authorization_code.consumed")
            .count(),
        1
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "token.issuance.result")
            .count(),
        1
    );
    assert_eq!(
        sink.outcome_of("authorization_code.consumed"),
        Some("success")
    );
    assert_eq!(sink.outcome_of("token.issuance.result"), Some("success"));
    let events = sink.events.lock().unwrap();
    let issuance = events
        .iter()
        .find(|event| event.name == "token.issuance.result")
        .unwrap();
    assert!(issuance.attributes.iter().any(|(key, value)| {
        *key == "authorization_code_id"
            && *value == crate::observability::EventValue::Text(record.oid.to_string())
    }));
    // The user identifier is pseudonymized, never raw.
    assert!(issuance.attributes.iter().any(|(key, value)| {
        *key == "user_oid"
            && matches!(
                value,
                crate::observability::EventValue::Pseudonymized { purpose, .. } if *purpose == "user_oid"
            )
    }));
}

#[tokio::test]
async fn failed_exchange_emits_a_single_rejected_issuance_event() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let (service, _) = rs256_token_service_with_public_key(repo.clone(), user_oid);
    let sink = Arc::new(RecordingSink::default());
    let service = service.with_events(sink.clone());
    let code_oid = Uuid::new_v4();

    let error = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: Vec::new(),
            code: STANDARD.encode(code_oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_owned()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
        })
        .await
        .unwrap_err();

    assert!(error.code() > 0);
    let names = sink.names();
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "token.issuance.result")
            .count(),
        1
    );
    assert_eq!(sink.outcome_of("token.issuance.result"), Some("rejected"));
    sink.assert_attribute(
        "token.issuance.result",
        "rejected",
        "authorization_code_id",
        crate::observability::EventValue::Text(code_oid.to_string()),
    );
    // No code was ever consumed, so no consumption event is fabricated.
    assert!(!names.contains(&"authorization_code.consumed"));
}

#[tokio::test]
async fn code_exchange_inherits_global_oauth_version_and_honors_client_override() {
    use crate::openid_connect::tests::fixtures::client::ConfiguredClientRepository;
    use crate::setting::{
        AppSettings, InstallationSettings, OpenIdConnectSettings, SettingsSnapshot,
    };
    use identity_domain::openid_connect::{
        OAuthProtocolVersion, OpenIdConnectClientSettings, TokenEndpointAuthMethod,
    };

    for (global, client, may_omit_redirect) in [
        (OAuthProtocolVersion::V2_0, None, false),
        (OAuthProtocolVersion::V2_1, None, true),
        (
            OAuthProtocolVersion::V2_1,
            Some(OAuthProtocolVersion::V2_0),
            false,
        ),
        (
            OAuthProtocolVersion::V2_0,
            Some(OAuthProtocolVersion::V2_1),
            true,
        ),
    ] {
        let repo = Arc::new(mock_client_auth_repo());
        let user_oid = Uuid::new_v4();
        let record = repo
            .create(
                Uuid::nil(),
                ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                    resources: Vec::new(),
                    scope: "profile".to_owned(),
                    nonce: None,
                    code_challenge: Some(s256_challenge("verifier-123")),
                    code_challenge_method: Some("S256".parse().unwrap()),
                    user_oid: user_oid.to_string(),
                    session_oid: SessionOid::from(Uuid::new_v4()),
                    protected_session_id: None,
                    acr: None,
                    amr: vec![],
                    auth_time: None,
                    redirect_uri: "https://client.example.com/callback".to_owned(),
                    redirect_uri_was_supplied: true,
                    claims: None,
                }),
                Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .unwrap();
        let mut service = build_token_service_with_client_repo(
            repo,
            user_oid,
            Arc::new(ConfiguredClientRepository {
                settings: OpenIdConnectClientSettings {
                    require_pushed_authorization_requests: false,
                    oauth_version: client,
                    ..Default::default()
                },
                methods: vec![TokenEndpointAuthMethod::ClientSecretBasic],
            }),
        );
        service.provider_service = Arc::new(OpenIdProviderService::new(Arc::new(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    ..Default::default()
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    ..Default::default()
                })
                .with_section(&OpenIdConnectSettings {
                    oauth_version: global,
                    ..Default::default()
                }),
        )));
        let result = service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                resources: Vec::new(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: None,
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_owned()),
                client_secret_basic: true,
                client_assertion_type: None,
                client_assertion: None,
                code_verifier: Some("verifier-123".to_owned()),
            })
            .await;
        if may_omit_redirect {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().code(), 24007);
        }
    }
}
