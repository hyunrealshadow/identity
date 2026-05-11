use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;

#[tokio::test]
async fn exchange_refresh_token_returns_new_access_token() {
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let refresh_record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-refresh".to_string()),
                code_challenge: Some("verifier-refresh".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: Uuid::new_v4().to_string(),
                protected_session_id: None,
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

    let initial_refresh_token = initial.refresh_token.unwrap();
    let initial_refresh_oid =
        Uuid::from_slice(&STANDARD.decode(&initial_refresh_token).unwrap()).unwrap();

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            grant_type: "refresh_token".to_string(),
            refresh_token: initial_refresh_token,
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
    let rotated_oid = Uuid::from_slice(
        &STANDARD
            .decode(refreshed.refresh_token.as_ref().unwrap())
            .unwrap(),
    )
    .unwrap();
    let rotated = repo.find_by_oid(rotated_oid).await.unwrap();
    let rotated = rotated.unwrap();
    assert_eq!(rotated.type_, ClientAuthorizationType::RefreshToken);
    let rotated_data: RefreshTokenData = serde_json::from_value(rotated.data).unwrap();
    let expected_rotated_from = initial_refresh_oid.to_string();
    assert_eq!(
        rotated_data.rotated_from.as_deref(),
        Some(expected_rotated_from.as_str())
    );
}

#[tokio::test]
async fn exchange_refresh_token_accepts_protected_refresh_token_with_es256_signing_key() {
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let key = key_data_for_algorithm("ES256");
    let signing_key = Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: key.public_key.clone(),
            private_key: key.private_key.clone(),
            certificate: Some("ES256".to_owned()),
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };
    let binding = key_jwk_binding(
        &signing_key,
        &key_data_algorithm(&signing_key),
        Uuid::new_v4(),
    );
    let service = TokenService::new(
        repo.clone(),
        Arc::new(InMemoryKeyRepository {
            keys: vec![signing_key],
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![binding],
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
        signing_algorithm_detector(),
        InMemoryDataProtector::new(),
    );

    let refresh_record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-refresh-es256".to_string()),
                code_challenge: Some("verifier-refresh-es256".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: Uuid::new_v4().to_string(),
                protected_session_id: None,
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

#[tokio::test]
async fn refresh_token_preserves_auth_time_from_original_authentication() {
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = rsa.public_key_to_pem().unwrap();
    let public_key_string = String::from_utf8(public_key.clone()).unwrap();
    let signing_key = Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: public_key_string,
            private_key,
            certificate: None,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };
    let binding = key_jwk_binding(
        &signing_key,
        &key_data_algorithm(&signing_key),
        Uuid::new_v4(),
    );
    let service = TokenService::new(
        repo.clone(),
        Arc::new(InMemoryKeyRepository {
            keys: vec![signing_key],
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![binding],
        }),
        Arc::new(InMemoryUserRepository {
            user: User {
                oid: UserOid(user_oid),
                email: "auth-time@example.com".to_string(),
                email_normalized: "auth-time@example.com".to_string(),
                name: "Auth Time".to_string(),
                name_normalized: "auth time".to_string(),
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
        signing_algorithm_detector(),
        InMemoryDataProtector::new(),
    );
    let original_auth_time: i64 = 1713500000;

    let refresh_record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-auth-time".to_string()),
                code_challenge: Some("verifier-auth-time".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: Uuid::new_v4().to_string(),
                protected_session_id: None,
                acr: None,
                auth_time: Some(original_auth_time),
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
            code_verifier: Some("verifier-auth-time".to_string()),
        })
        .await
        .unwrap();

    let initial_refresh_token = initial.refresh_token.unwrap();
    let initial_refresh_oid =
        Uuid::from_slice(&STANDARD.decode(&initial_refresh_token).unwrap()).unwrap();
    let initial_stored = repo
        .find_by_oid(initial_refresh_oid)
        .await
        .unwrap()
        .unwrap();
    let initial_data: RefreshTokenData =
        serde_json::from_value(initial_stored.data.clone()).unwrap();
    assert_eq!(initial_data.auth_time, Some(original_auth_time));

    let refreshed = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            grant_type: "refresh_token".to_string(),
            refresh_token: initial_refresh_token,
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap();

    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (access_payload, _) =
        jwt::decode_with_verifier(&refreshed.access_token, &verifier).unwrap();
    let (id_payload, _) =
        jwt::decode_with_verifier(refreshed.id_token.as_ref().unwrap(), &verifier).unwrap();
    assert_eq!(
        id_payload.claim(JwtClaimNames::AUTH_TIME).unwrap(),
        &serde_json::json!(original_auth_time)
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::AT_HASH).unwrap(),
        &serde_json::json!(expected_at_hash(&refreshed.access_token))
    );
    assert_eq!(
        id_payload.claim(JwtClaimNames::SID),
        access_payload.claim(JwtClaimNames::SID)
    );

    let refreshed_token = refreshed.refresh_token.unwrap();
    let refreshed_oid = Uuid::from_slice(&STANDARD.decode(&refreshed_token).unwrap()).unwrap();
    let refreshed_stored = repo.find_by_oid(refreshed_oid).await.unwrap().unwrap();
    let refreshed_data: RefreshTokenData =
        serde_json::from_value(refreshed_stored.data.clone()).unwrap();
    assert_eq!(
        refreshed_data.auth_time,
        Some(original_auth_time),
        "auth_time should be preserved across refresh"
    );
}

#[tokio::test]
async fn refresh_token_stores_none_auth_time_when_code_has_none() {
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let refresh_record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access".to_string(),
                nonce: None,
                code_challenge: Some("verifier-no-auth-time".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: Uuid::new_v4().to_string(),
                protected_session_id: None,
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
            code_verifier: Some("verifier-no-auth-time".to_string()),
        })
        .await
        .unwrap();

    let refresh_token = initial.refresh_token.unwrap();
    let refresh_oid = Uuid::from_slice(&STANDARD.decode(&refresh_token).unwrap()).unwrap();
    let stored = repo.find_by_oid(refresh_oid).await.unwrap().unwrap();
    let data: RefreshTokenData = serde_json::from_value(stored.data).unwrap();
    assert_eq!(data.auth_time, None);
}
