use crate::key::asymmetric::AsymmetricKeyService;
use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;
use identity_domain::auth::ACR_PASSWORD;
use identity_domain::auth::SessionOid;
use identity_domain::key::{KeyJwk, KeyJwkOid, PublicJwk};

fn rs256_token_service_with_public_key(
    repo: Arc<InMemoryClientAuthorizationRepository>,
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
async fn exchange_authorization_code_revokes_code_after_success() {
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let (service, public_key) = rs256_token_service_with_public_key(repo.clone(), user_oid);

    let session_oid = Uuid::new_v4();
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some("verifier-123".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(session_oid),
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
async fn exchange_authorization_code_keeps_email_scope_claims_out_of_id_token() {
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let (service, public_key) = rs256_token_service_with_public_key(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "email openid".to_string(),
                nonce: Some("nonce-123".to_string()),
                code_challenge: Some("verifier-123".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: Some(ACR_PASSWORD.to_string()),
                auth_time: Some(chrono::Utc::now().timestamp()),
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
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: None,
                code_challenge: Some("expected-verifier".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
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
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let key = key_for_algorithm("RS256");
    let public_key = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.as_bytes().to_vec(),
        KeyData::Symmetric(_) => unreachable!("test signing key must be asymmetric"),
    };
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());
    let key_repo = Arc::new(InMemoryKeyRepository {
        keys: vec![key.clone()],
    });
    let user = test_user(user_oid);
    let service = TokenService::new(
        repo.clone(),
        key_repo.clone(),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![binding],
        }),
        Arc::new(InMemoryUserRepository { user: user.clone() }),
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

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: None,
                code_challenge: Some("verifier-789".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
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

    let code = STANDARD.encode(record.oid.as_bytes());
    let first_response = service
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
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (access_payload, _) =
        jwt::decode_with_verifier(&first_response.access_token, &verifier).unwrap();
    let access_token_jti = access_payload.jwt_id().unwrap().to_string();

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
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let service = build_token_service(repo.clone(), user_oid);

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid offline_access profile".to_string(),
                nonce: Some("nonce-offline".to_string()),
                code_challenge: Some("verifier-offline".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
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
        let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
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
                ClientAuthorizationType::AuthorizationCode,
                serde_json::to_value(AuthorizationCodeData {
                    scope: "openid profile".to_string(),
                    nonce: Some(format!("nonce-{alg}")),
                    code_challenge: Some(format!("verifier-{alg}")),
                    code_challenge_method: Some("plain".to_string()),
                    user_oid: user_oid.to_string(),
                    session_oid: SessionOid::from(Uuid::new_v4()),
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

        let result = service
            .exchange_authorization_code(AuthorizationCodeGrantParams {
                grant_type: "authorization_code".to_string(),
                code: STANDARD.encode(record.oid.as_bytes()),
                redirect_uri: Some("https://client.example.com/callback".to_string()),
                client_id: Some(Uuid::nil().to_string()),
                client_secret: Some("secret-123".to_string()),
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
    let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let user_oid = Uuid::new_v4();
    let key = key_for_algorithm("RS256");
    let binding_oid = Uuid::new_v4();
    let binding = KeyJwk {
        oid: KeyJwkOid::from(binding_oid),
        key_oid: key.oid,
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
    };
    let public_key = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.clone(),
        KeyData::Symmetric(_) => unreachable!(),
    };

    let service = TokenService::new(
        repo.clone(),
        Arc::new(InMemoryKeyRepository {
            keys: vec![key.clone()],
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![binding],
        }),
        Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
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

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationType::AuthorizationCode,
            serde_json::to_value(AuthorizationCodeData {
                scope: "openid profile".to_string(),
                nonce: Some("nonce-rs256".to_string()),
                code_challenge: Some("verifier-rs256".to_string()),
                code_challenge_method: Some("plain".to_string()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
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

    let result = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            grant_type: "authorization_code".to_string(),
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
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
async fn ps_algorithms_sign_tokens_and_validate_userinfo() {
    for alg in ["PS256", "PS384", "PS512"] {
        let repo = Arc::new(InMemoryClientAuthorizationRepository::default());
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
            .create_access_token_record(
                Uuid::nil(),
                "openid profile",
                &user_oid.to_string(),
                SessionOid::from(Uuid::new_v4()),
                None,
                None,
            )
            .await
            .unwrap();
        let access_token = service
            .sign_access_token(
                &access_record.oid.to_string(),
                &key_id,
                &private_key,
                alg,
                &issuer,
                &Uuid::nil().to_string(),
                &Uuid::nil().to_string(),
                &user_oid,
                &Uuid::new_v4().to_string(),
                "openid profile",
                None,
            )
            .unwrap();
        let client = service
            .client_repo
            .find_by_oid(Uuid::nil())
            .await
            .unwrap()
            .unwrap();
        let id_token = service
            .sign_id_token(
                &key_id,
                &private_key,
                alg,
                &issuer,
                &Uuid::nil().to_string(),
                &client,
                &test_user(user_oid),
                None,
                None,
                None,
                Some(&access_token),
                None,
                "openid profile",
            )
            .unwrap();

        let access_payload = decode_jwt_with_alg(&access_token, &public_key, alg);
        let id_payload = decode_jwt_with_alg(&id_token, &public_key, alg);
        assert_eq!(access_payload.subject().unwrap(), user_oid.to_string());
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
