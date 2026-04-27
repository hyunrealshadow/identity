use super::super::fixtures::*;
use super::super::*;

#[tokio::test]
async fn exchange_refresh_token_returns_new_access_token() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let refresh_record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-refresh".to_string()),
                code_challenge: Some("verifier-refresh".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: Uuid::new_v4().to_string(),
                acr: None,
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                claims: None,
            })
            .unwrap(),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let initial = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code: STANDARD.encode(refresh_record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-refresh".to_string()),
        })
        .await
        .unwrap();

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            grant_type: "refresh_token".to_string(),
            refresh_token: initial.refresh_token.unwrap(),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap();

    assert_eq!(refreshed.token_type, "Bearer");
    assert!(refreshed.id_token.is_some());
    assert!(refreshed.refresh_token.is_some());
    let rotated = repo
        .find_refresh_token_by_token(refreshed.refresh_token.as_ref().unwrap())
        .await
        .unwrap();
    assert!(rotated.is_some());
}

#[tokio::test]
async fn exchange_refresh_token_accepts_es256_signed_refresh_token() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let generator = AsymmetricKeyGeneratorImpl;
    let key = generator
        .generate(&crate::domain::key::generator::AsymmetricKeySpec {
            algorithm: crate::domain::key::model::AsymmetricKeyAlgorithm::EcdsaP256,
        })
        .unwrap();
    let service = TokenService::new(
        repo.clone(),
        Arc::new(InMemoryKeyRepository {
            keys: vec![Key {
                oid: KeyOid(Uuid::new_v4()),
                r#type: KeyType::Asymmetric,
                data: KeyData::Asymmetric(AsymmetricKeyData {
                    public_key: key.public_key.clone(),
                    private_key: key.private_key.clone(),
                    certificate: None,
                }),
                expires_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }],
        }),
        Arc::new(InMemoryUserRepository {
            user: User {
                oid: UserOid(user_oid),
                email: "es256-refresh@example.com".to_string(),
                email_normalized: "es256-refresh@example.com".to_string(),
                name: "ES256 Refresh".to_string(),
                name_normalized: "es256 refresh".to_string(),
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
            },
        }),
        Arc::new(InMemoryClientRepository),
        Arc::new(InMemoryCredentialRepository {
            credentials: vec![OpenIdConnectCredential {
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
            }],
        }),
        provider_service(),
        InMemoryDataProtector::new(),
    );

    let refresh_record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-refresh-es256".to_string()),
                code_challenge: Some("verifier-refresh-es256".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: Uuid::new_v4().to_string(),
                acr: None,
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                claims: None,
            })
            .unwrap(),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let initial = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code: STANDARD.encode(refresh_record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-refresh-es256".to_string()),
        })
        .await
        .unwrap();

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            grant_type: "refresh_token".to_string(),
            refresh_token: initial.refresh_token.unwrap(),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
        })
        .await;

    assert!(refreshed.is_ok());
}
