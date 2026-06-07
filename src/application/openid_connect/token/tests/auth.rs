use super::fixtures::*;
use super::*;

fn default_user(email: &str) -> User {
    User {
        oid: UserOid(Uuid::new_v4()),
        email: email.to_string(),
        email_normalized: email.to_string(),
        name: email.to_string(),
        name_normalized: email.to_string(),
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

#[tokio::test]
async fn authenticate_client_secret_basic_accepts_matching_secret() {
    let service = build_token_service(Arc::new(mock_client_auth_repo()), Uuid::new_v4());

    let result = service
        .authenticate_client_secret_basic("00000000-0000-0000-0000-000000000000", "secret-123")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_basic_rejects_wrong_secret() {
    let service = build_token_service(Arc::new(mock_client_auth_repo()), Uuid::new_v4());

    let result = service
        .authenticate_client_secret_basic("00000000-0000-0000-0000-000000000000", "wrong-secret")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_client_secret_post_accepts_matching_secret() {
    let service = build_token_service(Arc::new(mock_client_auth_repo()), Uuid::new_v4());

    let result = service
        .authenticate_client_secret_post("00000000-0000-0000-0000-000000000000", "secret-123")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_jwt_accepts_hs256_assertion() {
    let service = build_token_service_with_auth_method("client_secret_jwt");
    let assertion = build_client_secret_assertion(
        CLIENT_SECRET_JWT_SECRET,
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_client(
            "00000000-0000-0000-0000-000000000000",
            None,
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            Some(&assertion),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_jwt_uses_registered_signing_algorithm() {
    let service = build_token_service_with_auth_method_and_alg("client_secret_jwt", Some("HS384"));
    let assertion = build_client_secret_assertion_with_algorithm(
        CLIENT_SECRET_JWT_SECRET,
        "HS384",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_client(
            "00000000-0000-0000-0000-000000000000",
            None,
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            Some(&assertion),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_jwt_rejects_unregistered_signing_algorithm() {
    let service = build_token_service_with_auth_method_and_alg("client_secret_jwt", Some("HS384"));
    let assertion = build_client_secret_assertion_with_algorithm(
        CLIENT_SECRET_JWT_SECRET,
        "HS256",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let error = service
        .authenticate_client(
            "00000000-0000-0000-0000-000000000000",
            None,
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            Some(&assertion),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24039);
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_signed_assertion() {
    let service = build_token_service(Arc::new(mock_client_auth_repo()), Uuid::new_v4());
    let assertion = service
        .build_client_assertion_for_test("00000000-0000-0000-0000-000000000000")
        .await;

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_private_key_jwt_rejects_wrong_subject() {
    let service = build_token_service(Arc::new(mock_client_auth_repo()), Uuid::new_v4());
    let assertion = service
        .build_client_assertion_for_test("11111111-1111-1111-1111-111111111111")
        .await;

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_private_key_jwt_rejects_missing_exp() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let service = TokenService::new(TokenServiceDependencies {
        client_authorization_repo: repo,
        key_repo: Arc::new(key_repo_with_keys(vec![key_for_algorithm("RS256")])),
        key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![])),
        user_repo: Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
        }),
        client_repo: Arc::new(InMemoryClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            r#type: OpenIdConnectCredentialType::ClientPublicKey,
            hint: "private_key_jwt".to_owned(),
            data: OpenIdConnectCredentialData::ClientPublicKey {
                public_key,
                jwk: None,
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

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    let now = std::time::SystemTime::now();
    payload.set_issuer(Uuid::nil().to_string());
    payload.set_subject(Uuid::nil().to_string());
    payload.set_audience(vec!["https://identity.example.com/oauth2/token"]);
    payload.set_issued_at(&now);
    payload.set_jwt_id(Uuid::new_v4().to_string());
    let assertion = jwt::encode_with_signer(
        &payload,
        &header,
        &*RS256.signer_from_pem(private_key.as_bytes()).unwrap(),
    )
    .unwrap();

    let result = service
        .authenticate_private_key_jwt(&Uuid::nil().to_string(), &assertion)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_client_rejects_public_flow_by_default() {
    let service = build_token_service(Arc::new(mock_client_auth_repo()), Uuid::new_v4());

    let error = service
        .authenticate_client("00000000-0000-0000-0000-000000000000", None, None, None)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24031);
}

#[tokio::test]
async fn authenticate_client_accepts_public_flow_when_enabled() {
    let service = TokenService::new(TokenServiceDependencies {
        client_authorization_repo: Arc::new(mock_client_auth_repo()),
        key_repo: Arc::new(key_repo_with_keys(vec![])),
        key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![])),
        user_repo: Arc::new(InMemoryUserRepository {
            user: default_user("public@example.com"),
        }),
        client_repo: Arc::new(PublicFlowClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![])),
        provider_service: provider_service(),
        signing_algorithm_detector: signing_algorithm_detector(),
        data_protector: InMemoryDataProtector::new(),
    });

    let client_oid = service
        .authenticate_client("00000000-0000-0000-0000-000000000000", None, None, None)
        .await
        .unwrap();

    assert_eq!(client_oid, Uuid::nil());
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_es256_signed_assertion() {
    let repo = Arc::new(mock_client_auth_repo());
    let key = key_data_for_algorithm("ES256");
    let service = TokenService::new(TokenServiceDependencies {
        client_authorization_repo: repo,
        key_repo: Arc::new(key_repo_with_keys(vec![])),
        key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![])),
        user_repo: Arc::new(InMemoryUserRepository {
            user: default_user("es256@example.com"),
        }),
        client_repo: Arc::new(InMemoryClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            r#type: OpenIdConnectCredentialType::ClientPublicKey,
            hint: "private_key_jwt".to_string(),
            data: OpenIdConnectCredentialData::ClientPublicKey {
                public_key: key.public_key.clone(),
                jwk: None,
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

    let assertion = build_client_assertion_with_algorithm(
        &key.private_key,
        "ES256",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_eddsa_signed_assertion() {
    let repo = Arc::new(mock_client_auth_repo());
    let key = key_data_for_algorithm("EdDSA");
    let service = TokenService::new(TokenServiceDependencies {
        client_authorization_repo: repo,
        key_repo: Arc::new(key_repo_with_keys(vec![])),
        key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![])),
        user_repo: Arc::new(InMemoryUserRepository {
            user: default_user("eddsa@example.com"),
        }),
        client_repo: Arc::new(InMemoryClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            r#type: OpenIdConnectCredentialType::ClientPublicKey,
            hint: "private_key_jwt".to_string(),
            data: OpenIdConnectCredentialData::ClientPublicKey {
                public_key: key.public_key.clone(),
                jwk: None,
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

    let assertion = build_client_assertion_with_algorithm(
        &key.private_key,
        "EdDSA",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_ok());
}
