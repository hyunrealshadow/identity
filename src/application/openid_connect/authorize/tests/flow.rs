use super::fixtures::*;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_domain::client_authorization::{ConsentState, SelectionSource};
use identity_domain::key::material::AsymmetricKeyData;
use identity_domain::openid_connect::model::claim::JwtClaimNames;
use sha2::{Digest, Sha256};

struct HybridUserRepository {
    user: User,
}

#[async_trait]
impl UserRepository for HybridUserRepository {
    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        Ok((self.user.oid == oid).then_some(self.user.clone()))
    }

    async fn find_by_identifier(&self, _identifier: &str) -> Result<User, UserRepositoryError> {
        Err(UserRepositoryError::UserNotFound)
    }

    async fn increment_failed_attempts(
        &self,
        _user_oid: UserOid,
        _lock_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), UserRepositoryError> {
        Ok(())
    }

    async fn reset_failed_attempts(&self, _user_oid: UserOid) -> Result<(), UserRepositoryError> {
        Ok(())
    }
}

struct HybridKeyRepository {
    oid: KeyOid,
    private_key: String,
}

#[async_trait]
impl KeyRepository for HybridKeyRepository {
    async fn find_by_oid(&self, _oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
        Ok(None)
    }

    async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        Ok(vec![Key {
            oid: self.oid,
            r#type: KeyType::Asymmetric,
            data: KeyData::Asymmetric(AsymmetricKeyData {
                public_key: String::new(),
                private_key: self.private_key.clone(),
                certificate: None,
            }),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }])
    }

    async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        Ok(vec![])
    }

    async fn create(
        &self,
        _key_type: KeyType,
        _data: &KeyData,
        _expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<Key, KeyRepositoryError> {
        unreachable!()
    }

    async fn update_certificate_by_oid(
        &self,
        _oid: KeyOid,
        _certificate_pem: &str,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        unreachable!()
    }

    async fn revoke_by_oid(
        &self,
        _oid: KeyOid,
        _revoked_at: chrono::DateTime<Utc>,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        unreachable!()
    }
}

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
        Arc::new(EmptyKeyJwkRepository),
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
        Arc::new(EmptyKeyJwkRepository),
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
        Arc::new(EmptyKeyJwkRepository),
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
async fn create_authorization_request_stores_wrapped_request_with_pending_interaction() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

    let (request, _) = service
        .validate_request(params("openid profile"))
        .await
        .unwrap();
    let oid = request_repo.insert_legacy_authorization_request_for_test(&request);
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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
            Uuid::new_v4(),
            Uuid::new_v4(),
            SelectionSource::Auto,
        )
        .await
        .unwrap();

    let fresh_session = Uuid::new_v4();
    let fresh_user = Uuid::new_v4();
    service
        .record_authorization_selection(
            authorization_oid,
            fresh_session,
            fresh_user,
            SelectionSource::FreshLogin,
        )
        .await
        .unwrap();

    let stored = service
        .load_stored_authorization_request(authorization_oid)
        .await
        .unwrap();

    assert_eq!(
        stored.interaction.selected_session_oid.as_deref(),
        Some(fresh_session.to_string().as_str())
    );
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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
        .approve_authorization_request(authorization_oid, Uuid::new_v4(), Uuid::new_v4(), None)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23062);
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
        Arc::new(EmptyKeyJwkRepository),
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
    assert!(query.contains("session_state="));
}

#[tokio::test]
async fn approve_authorization_request_failure_does_not_burn_interaction() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
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
    request_repo.set_stored_request_redirect_uri_for_test(oid, "not a uri");

    let error = service
        .approve_authorization_request(oid, Uuid::new_v4(), Uuid::new_v4(), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), 23052);
    assert_eq!(request_repo.completed_at_for_test(oid), None);

    request_repo
        .set_stored_request_redirect_uri_for_test(oid, "https://client.example.com/callback");

    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), Uuid::new_v4(), None)
        .await
        .unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("code="));
    assert!(query.contains("state=state123"));
    assert!(request_repo.completed_at_for_test(oid).is_some());
}

#[tokio::test]
async fn approve_code_id_token_hybrid_returns_fragment_with_code_and_id_token_hash() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let binding_oid = Uuid::new_v4();
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo,
        Arc::new(InMemoryLoginRepository),
        Arc::new(HybridUserRepository {
            user: hybrid_user(user_oid),
        }),
        Arc::new(HybridKeyRepository {
            oid: key_oid,
            private_key: std::str::from_utf8(&private_key).unwrap().to_string(),
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![hybrid_binding(key_oid, binding_oid)],
        }),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

    let mut request_params = params("openid profile");
    request_params.response_type = "code id_token".to_string();
    request_params.nonce = Some("nonce-hybrid".to_string());
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), user_oid, None)
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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let (private_key, _public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo,
        Arc::new(InMemoryLoginRepository),
        Arc::new(HybridUserRepository {
            user: hybrid_user(user_oid),
        }),
        Arc::new(HybridKeyRepository {
            oid: key_oid,
            private_key: std::str::from_utf8(&private_key).unwrap().to_string(),
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![hybrid_binding(key_oid, Uuid::new_v4())],
        }),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

    let mut request_params = params("openid profile");
    request_params.response_type = "id_token".to_string();
    request_params.nonce = Some("nonce-implicit".to_string());
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), user_oid, None)
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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let (private_key, public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo,
        Arc::new(InMemoryLoginRepository),
        Arc::new(HybridUserRepository {
            user: hybrid_user(user_oid),
        }),
        Arc::new(HybridKeyRepository {
            oid: key_oid,
            private_key: std::str::from_utf8(&private_key).unwrap().to_string(),
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![hybrid_binding(key_oid, Uuid::new_v4())],
        }),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

    let mut request_params = params("openid profile");
    request_params.response_type = "code id_token token".to_string();
    request_params.nonce = Some("nonce-hybrid".to_string());
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), user_oid, None)
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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let (private_key, _public_key) = signing_keypair();
    let user_oid = Uuid::new_v4();
    let key_oid = KeyOid::from(Uuid::new_v4());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo,
        Arc::new(InMemoryLoginRepository),
        Arc::new(HybridUserRepository {
            user: hybrid_user(user_oid),
        }),
        Arc::new(HybridKeyRepository {
            oid: key_oid,
            private_key: std::str::from_utf8(&private_key).unwrap().to_string(),
        }),
        Arc::new(InMemoryKeyJwkRepository {
            bindings: vec![hybrid_binding(key_oid, Uuid::new_v4())],
        }),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

    let mut request_params = params("openid profile");
    request_params.response_type = "code token".to_string();
    let (request, _) = service.validate_request(request_params).await.unwrap();
    let oid = service
        .create_authorization_request(&request)
        .await
        .unwrap();
    let redirect = service
        .approve_authorization_request(oid, Uuid::new_v4(), user_oid, None)
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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
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
async fn create_authorization_request_persists_prompt() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
        provider_service(),
        test_signing_algorithm_detector(),
        test_data_protector(),
    );

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
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
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

#[tokio::test]
async fn deny_authorization_request_failure_does_not_burn_interaction() {
    let request_repo = Arc::new(InMemoryClientAuthorizationRepository::default());
    let service = AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        request_repo.clone(),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        Arc::new(EmptyKeyJwkRepository),
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
    request_repo.set_stored_request_redirect_uri_for_test(oid, "not a uri");

    let error = service.deny_authorization_request(oid).await.unwrap_err();
    assert_eq!(error.code(), 23052);
    assert_eq!(request_repo.completed_at_for_test(oid), None);

    request_repo
        .set_stored_request_redirect_uri_for_test(oid, "https://client.example.com/callback");

    let redirect = service.deny_authorization_request(oid).await.unwrap();

    let query = redirect.query().unwrap();
    assert!(query.contains("error=access_denied"));
    assert!(query.contains("state=state123"));
    assert!(request_repo.completed_at_for_test(oid).is_some());
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
            None,
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

#[test]
fn sign_implicit_id_token_omits_scope_claims_when_code_is_returned() {
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
            None,
            Some("authorization-code"),
            &scope,
            None,
        )
        .unwrap();
    let verifier = RS256.verifier_from_pem(&public_key).unwrap();
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier).unwrap();

    assert_eq!(payload.claim("email"), None);
    assert_eq!(payload.claim("name"), None);
    assert!(payload.claim("c_hash").is_some());
}
