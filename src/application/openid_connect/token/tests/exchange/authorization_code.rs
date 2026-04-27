use super::super::fixtures::*;
use super::super::*;

#[tokio::test]
async fn exchange_authorization_code_revokes_code_after_success() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = rsa.public_key_to_pem().unwrap();
    let service = TokenService::new(
        repo.clone(),
        Arc::new(InMemoryKeyRepository {
            keys: vec![Key {
                oid: KeyOid(Uuid::new_v4()),
                r#type: KeyType::Asymmetric,
                data: KeyData::Asymmetric(AsymmetricKeyData {
                    public_key: String::from_utf8(public_key.clone()).unwrap(),
                    private_key,
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
                email: "alice@example.com".to_string(),
                email_normalized: "alice@example.com".to_string(),
                name: "Alice".to_string(),
                name_normalized: "alice".to_string(),
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

    let record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some("verifier-123".to_string()),
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

    let code = STANDARD.encode(record.oid.as_bytes());
    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code,
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-123".to_string()),
        })
        .await
        .unwrap();

    assert_eq!(result.token_type, "Bearer");
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
async fn exchange_authorization_code_keeps_email_scope_claims_out_of_id_token() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = rsa.public_key_to_pem().unwrap();
    let service = TokenService::new(
        repo.clone(),
        Arc::new(InMemoryKeyRepository {
            keys: vec![Key {
                oid: KeyOid(Uuid::new_v4()),
                r#type: KeyType::Asymmetric,
                data: KeyData::Asymmetric(AsymmetricKeyData {
                    public_key: String::from_utf8(public_key.clone()).unwrap(),
                    private_key,
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
                email: "alice@example.com".to_string(),
                email_normalized: "alice@example.com".to_string(),
                name: "Alice".to_string(),
                name_normalized: "alice".to_string(),
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

    let record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "email openid".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some("verifier-123".to_string()),
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

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
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
async fn exchange_authorization_code_rejects_invalid_pkce_verifier() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: None,
                code_challenge: Some("expected-verifier".to_string()),
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

    let code = STANDARD.encode(record.oid.as_bytes());
    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code,
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("wrong-verifier".to_string()),
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn exchange_authorization_code_rejects_reused_code() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: None,
                code_challenge: Some("verifier-789".to_string()),
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

    let code = STANDARD.encode(record.oid.as_bytes());
    service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code: code.clone(),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-789".to_string()),
        })
        .await
        .unwrap();

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code,
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-789".to_string()),
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn exchange_authorization_code_returns_refresh_token_for_offline_access() {
    let repo = Arc::new(InMemoryClientRequestRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientRequestType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-offline".to_string()),
                code_challenge: Some("verifier-offline".to_string()),
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

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: Some("verifier-offline".to_string()),
        })
        .await
        .unwrap();

    assert!(result.refresh_token.is_some());
    let stored = repo
        .find_refresh_token_by_token(result.refresh_token.as_ref().unwrap())
        .await
        .unwrap();
    assert!(stored.is_some());
}
