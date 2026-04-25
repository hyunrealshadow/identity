use super::fixtures::*;
use super::*;

#[tokio::test]
async fn authenticate_client_secret_basic_accepts_matching_secret() {
    let service = build_token_service(
        Arc::new(InMemoryClientRequestRepository::default()),
        Uuid::new_v4(),
    );

    let result = service
        .authenticate_client_secret_basic("00000000-0000-0000-0000-000000000000", "secret-123")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_basic_rejects_wrong_secret() {
    let service = build_token_service(
        Arc::new(InMemoryClientRequestRepository::default()),
        Uuid::new_v4(),
    );

    let result = service
        .authenticate_client_secret_basic("00000000-0000-0000-0000-000000000000", "wrong-secret")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_signed_assertion() {
    let service = build_token_service(
        Arc::new(InMemoryClientRequestRepository::default()),
        Uuid::new_v4(),
    );
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
    let service = build_token_service(
        Arc::new(InMemoryClientRequestRepository::default()),
        Uuid::new_v4(),
    );
    let assertion = service
        .build_client_assertion_for_test("11111111-1111-1111-1111-111111111111")
        .await;

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_es256_signed_assertion() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let generator = AsymmetricKeyGeneratorImpl;
    let key = generator
        .generate(&crate::domain::key::generator::AsymmetricKeySpec {
            algorithm: crate::domain::key::model::AsymmetricKeyAlgorithm::EcdsaP256,
        })
        .unwrap();
    let service = TokenService::new(
        repo,
        Arc::new(InMemoryKeyRepository { keys: vec![] }),
        Arc::new(InMemoryUserRepository {
            user: User {
                oid: UserOid(Uuid::new_v4()),
                email: "es256@example.com".to_string(),
                email_normalized: "es256@example.com".to_string(),
                name: "ES256".to_string(),
                name_normalized: "es256".to_string(),
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
                failed_attempts: 0,
                enabled: true,
                locked: false,
                locked_until: None,
                created_at: Utc::now(),
                updated_at: None,
            },
        }),
        Arc::new(InMemoryClientRepository),
        Arc::new(InMemoryCredentialRepository {
            credentials: vec![OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientPublicKey,
                hint: "private_key_jwt".to_string(),
                data: OpenIdConnectCredentialData::ClientPublicKey {
                    public_key: key.public_key.clone(),
                },
                expires_at: Utc::now() + chrono::Duration::days(1),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }],
        }),
        provider_service(),
        InMemoryDataProtector::new(),
    );

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
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let generator = AsymmetricKeyGeneratorImpl;
    let key = generator
        .generate(&crate::domain::key::generator::AsymmetricKeySpec {
            algorithm: crate::domain::key::model::AsymmetricKeyAlgorithm::Ed25519,
        })
        .unwrap();
    let service = TokenService::new(
        repo,
        Arc::new(InMemoryKeyRepository { keys: vec![] }),
        Arc::new(InMemoryUserRepository {
            user: User {
                oid: UserOid(Uuid::new_v4()),
                email: "eddsa@example.com".to_string(),
                email_normalized: "eddsa@example.com".to_string(),
                name: "EdDSA".to_string(),
                name_normalized: "eddsa".to_string(),
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
                failed_attempts: 0,
                enabled: true,
                locked: false,
                locked_until: None,
                created_at: Utc::now(),
                updated_at: None,
            },
        }),
        Arc::new(InMemoryClientRepository),
        Arc::new(InMemoryCredentialRepository {
            credentials: vec![OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientPublicKey,
                hint: "private_key_jwt".to_string(),
                data: OpenIdConnectCredentialData::ClientPublicKey {
                    public_key: key.public_key.clone(),
                },
                expires_at: Utc::now() + chrono::Duration::days(1),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }],
        }),
        provider_service(),
        InMemoryDataProtector::new(),
    );

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
