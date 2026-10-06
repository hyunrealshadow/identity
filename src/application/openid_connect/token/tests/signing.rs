use serde_json::{from_value, json, to_value};

use super::*;

pub(super) fn expected_at_hash(access_token: &str) -> String {
    expected_at_hash_for_alg(access_token, "RS256")
}

pub(super) fn expected_at_hash_for_alg(access_token: &str, alg: &str) -> String {
    match alg {
        "RS384" | "PS384" | "ES384" => {
            let digest = Sha384::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..24])
        }
        "RS512" | "PS512" | "ES512" | "EdDSA" => {
            let digest = Sha512::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..32])
        }
        _ => {
            let digest = Sha256::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..16])
        }
    }
}

pub(super) fn key_jwk_binding(key: &Key, alg: &str, binding_oid: Uuid) -> KeyJwk {
    let private_key = match &key.data {
        KeyData::Asymmetric(data) => data.private_key.as_str(),
        KeyData::Symmetric(_) => panic!("signing key bindings require asymmetric keys"),
    };

    let mut jwk = if let Ok(key_pair) = RsaPssKeyPair::from_pem(private_key, None, None, None) {
        key_pair.to_jwk_public_key()
    } else if let Ok(key_pair) = RsaKeyPair::from_pem(private_key) {
        key_pair.to_jwk_public_key()
    } else if let Ok(key_pair) = EcKeyPair::from_pem(private_key, None) {
        key_pair.to_jwk_public_key()
    } else if let Ok(key_pair) = EdKeyPair::from_pem(private_key) {
        key_pair.to_jwk_public_key()
    } else {
        panic!("unsupported test key format");
    };

    jwk.set_key_use("sig");
    jwk.set_algorithm(alg);
    jwk.set_key_id(binding_oid.to_string());

    KeyJwk {
        oid: KeyJwkOid::from(binding_oid),
        key_oid: key.oid,
        algorithm: alg.parse().unwrap(),
        jwk: from_value::<PublicJwk>(to_value(jwk).unwrap()).unwrap(),
        created_at: Utc::now(),
    }
}

pub(super) fn key_for_algorithm(alg: &str) -> Key {
    if let Some(data) = rsa_pss_key_for_algorithm(alg) {
        return Key {
            oid: KeyOid(Uuid::new_v4()),
            r#type: KeyType::Asymmetric,
            data: KeyData::Asymmetric(AsymmetricKeyData {
                certificate: Some(alg.to_owned()),
                ..data
            }),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        };
    }

    let data = key_data_for_algorithm(alg);
    Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            certificate: Some(alg.to_owned()),
            ..data
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

pub(super) fn key_data_for_algorithm(alg: &str) -> AsymmetricKeyData {
    match alg {
        "RS256" => rsa_key_data(2048),
        "RS384" => rsa_key_data(3072),
        "RS512" => rsa_key_data(4096),
        "ES256" => ec_key_data(EcCurve::P256),
        "ES384" => ec_key_data(EcCurve::P384),
        "ES512" => ec_key_data(EcCurve::P521),
        "ES256K" => ec_key_data(EcCurve::Secp256k1),
        "EdDSA" => ed_key_data(EdCurve::Ed25519),
        other => panic!("unsupported test alg: {other}"),
    }
}

pub(super) fn rsa_key_data(bits: u32) -> AsymmetricKeyData {
    let jwk = Jwk::generate_rsa_key(bits).unwrap();
    let key_pair = RsaKeyPair::from_jwk(&jwk).unwrap();
    AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    }
}

pub(super) fn ec_key_data(curve: EcCurve) -> AsymmetricKeyData {
    let jwk = Jwk::generate_ec_key(curve).unwrap();
    let key_pair = EcKeyPair::from_jwk(&jwk).unwrap();
    AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    }
}

pub(super) fn ed_key_data(curve: EdCurve) -> AsymmetricKeyData {
    let jwk = Jwk::generate_ed_key(curve).unwrap();
    let key_pair = EdKeyPair::from_jwk(&jwk).unwrap();
    AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    }
}

pub(super) struct TestKeyJwkGenerator;

pub(super) struct TestAsymmetricKeyGenerator;

impl AsymmetricKeyGenerator for TestAsymmetricKeyGenerator {
    fn generate(&self, _spec: &AsymmetricKeySpec) -> Result<AsymmetricKeyData, KeyMaterialError> {
        Ok(key_data_for_algorithm("RS256"))
    }
}

impl KeyJwkGenerator for TestKeyJwkGenerator {
    fn generate(
        &self,
        _private_key_pem: &str,
        _key_id: &str,
        _certificate_pem: Option<&str>,
    ) -> Result<Vec<GeneratedKeyJwk>, AppError> {
        Ok(vec![])
    }
}

pub(super) fn test_key_jwk_generator() -> Arc<dyn KeyJwkGenerator> {
    Arc::new(TestKeyJwkGenerator)
}

pub(super) fn rsa_pss_key_for_algorithm(alg: &str) -> Option<AsymmetricKeyData> {
    let (hash, salt_len) = match alg {
        "PS256" => (SHA_256, 32),
        "PS384" => (SHA_384, 48),
        "PS512" => (SHA_512, 64),
        _ => return None,
    };
    let key_pair = RsaPssKeyPair::generate(2048, hash, hash, salt_len).unwrap();

    Some(AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    })
}

pub(super) fn decode_jwt_with_alg(token: &str, public_key_pem: &str, alg: &str) -> JwtPayload {
    let public_key = public_key_pem.as_bytes();
    match alg {
        "RS256" => jwt::decode_with_verifier(token, &*RS256.verifier_from_pem(public_key).unwrap()),
        "RS384" => jwt::decode_with_verifier(token, &*RS384.verifier_from_pem(public_key).unwrap()),
        "RS512" => jwt::decode_with_verifier(token, &*RS512.verifier_from_pem(public_key).unwrap()),
        "PS256" => jwt::decode_with_verifier(token, &*PS256.verifier_from_pem(public_key).unwrap()),
        "PS384" => jwt::decode_with_verifier(token, &*PS384.verifier_from_pem(public_key).unwrap()),
        "PS512" => jwt::decode_with_verifier(token, &*PS512.verifier_from_pem(public_key).unwrap()),
        "ES256" => jwt::decode_with_verifier(token, &*ES256.verifier_from_pem(public_key).unwrap()),
        "ES384" => jwt::decode_with_verifier(token, &*ES384.verifier_from_pem(public_key).unwrap()),
        "ES512" => jwt::decode_with_verifier(token, &*ES512.verifier_from_pem(public_key).unwrap()),
        "ES256K" => {
            jwt::decode_with_verifier(token, &*ES256K.verifier_from_pem(public_key).unwrap())
        }
        "EdDSA" => jwt::decode_with_verifier(token, &*EdDSA.verifier_from_pem(public_key).unwrap()),
        other => panic!("unsupported test alg: {other}"),
    }
    .unwrap()
    .0
}

pub(super) fn build_token_service_with_key(
    repo: Arc<MockClientAuthorizationRepository>,
    key: Key,
    user_oid: Uuid,
) -> TokenService {
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());
    TokenService::new(TokenServiceDependencies {
        device_repo: Arc::new(MockDeviceAuthorizationRepository::new()),
        client_authorization_repo: repo,
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
            expires_at: Utc::now() + Duration::days(1),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }])),
        provider_service: provider_service(),
        signing_algorithm_detector: signing_algorithm_detector(),
        data_protector: InMemoryDataProtector::new(),
    })
}

pub(super) fn build_token_service_with_scoped_claims(
    repo: Arc<MockClientAuthorizationRepository>,
    user_oid: Uuid,
) -> (TokenService, Vec<u8>) {
    let key = key_for_algorithm("RS256");
    let public_key = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.as_bytes().to_vec(),
        KeyData::Symmetric(_) => unreachable!("test signing key must be asymmetric"),
    };
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());
    let user = test_user(user_oid);
    (
        TokenService::new(TokenServiceDependencies {
            device_repo: Arc::new(MockDeviceAuthorizationRepository::new()),
            client_authorization_repo: repo,
            key_repo: Arc::new(key_repo_with_keys(vec![key.clone()])),
            key_jwk_repo: Arc::new(jwk_repo_with_bindings(vec![binding])),
            user_repo: Arc::new(InMemoryUserRepository { user: user.clone() }),
            client_repo: Arc::new(ScopedClaimsClientRepository),
            credential_repo: Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientSecret,
                hint: "token".to_string(),
                data: OpenIdConnectCredentialData::ClientSecret {
                    secret: "secret-123".to_string(),
                },
                expires_at: Utc::now() + Duration::days(1),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }])),
            provider_service: provider_service(),
            signing_algorithm_detector: signing_algorithm_detector(),
            data_protector: InMemoryDataProtector::new(),
        }),
        public_key,
    )
}

pub(super) struct StaticRuntimeKeyRingProvider {
    value: Arc<RuntimeKeyRing>,
}

#[async_trait]
impl RuntimeKeyRingProvider for StaticRuntimeKeyRingProvider {
    fn current_value(&self) -> Arc<RuntimeKeyRing> {
        Arc::clone(&self.value)
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        Ok(())
    }
}

#[tokio::test]
pub(super) async fn signing_key_provider_avoids_hot_path_repository_queries() {
    let key = key_for_algorithm("RS256");
    let private_key_pem = match &key.data {
        KeyData::Asymmetric(data) => data.private_key.clone(),
        KeyData::Symmetric(_) => unreachable!(),
    };
    let provider = Arc::new(StaticRuntimeKeyRingProvider {
        value: Arc::new(RuntimeKeyRing::new(
            KeyRing::new(vec![]),
            Some(RuntimeSigningKey {
                key_id: Uuid::new_v4().to_string(),
                private_key_pem,
                algorithm: "RS256".parse().unwrap(),
            }),
        )),
    });

    let service = TokenService::new(TokenServiceDependencies {
        device_repo: Arc::new(MockDeviceAuthorizationRepository::new()),
        client_authorization_repo: Arc::new(MockClientAuthorizationRepository::new()),
        key_repo: Arc::new(MockKeyRepository::new()),
        key_jwk_repo: Arc::new(MockKeyJwkRepository::new()),
        user_repo: Arc::new(InMemoryUserRepository {
            user: test_user(Uuid::new_v4()),
        }),
        client_repo: Arc::new(InMemoryClientRepository),
        credential_repo: Arc::new(cred_repo_with(vec![])),
        provider_service: provider_service(),
        signing_algorithm_detector: signing_algorithm_detector(),
        data_protector: InMemoryDataProtector::new(),
    })
    .with_runtime_key_ring(provider);

    let first = service.load_signing_key().await.unwrap();
    let second = service.load_signing_key().await.unwrap();
    assert_eq!(first, second);
}

#[tokio::test]
pub(super) async fn id_token_key_selection_uses_client_algorithm_and_published_binding() {
    let rsa = key_for_algorithm("RS256");
    let ec = key_for_algorithm("ES256");
    let rsa_binding = key_jwk_binding(&rsa, "RS256", Uuid::new_v4());
    let ec_binding = key_jwk_binding(&ec, "ES256", Uuid::new_v4());
    let user_oid = Uuid::new_v4();
    let mut service =
        fixtures::build_token_service(Arc::new(MockClientAuthorizationRepository::new()), user_oid);
    service.key_repo = Arc::new(key_repo_with_keys(vec![rsa, ec]));
    service.key_jwk_repo = Arc::new(jwk_repo_with_bindings(vec![
        rsa_binding,
        ec_binding.clone(),
    ]));

    let (kid, _, alg) = service
        .load_configured_signing_key(Some(&[JwsAlgorithm::Asymmetric(
            JwaSigningAlgorithm::Es256,
        )]))
        .await
        .unwrap();
    assert_eq!(kid, Uuid::from(ec_binding.oid).to_string());
    assert_eq!(alg.as_str(), "ES256");
    let (_, _, fallback_alg) = service
        .load_configured_signing_key(Some(&[
            JwsAlgorithm::Asymmetric(JwaSigningAlgorithm::Es384),
            JwsAlgorithm::Asymmetric(JwaSigningAlgorithm::Es256),
        ]))
        .await
        .unwrap();
    assert_eq!(fallback_alg.as_str(), "ES256");
    assert!(
        service
            .load_configured_signing_key(Some(&[JwsAlgorithm::Asymmetric(
                JwaSigningAlgorithm::Es384,
            )]))
            .await
            .is_err(),
        "the OP must not silently sign with another algorithm"
    );
}

#[tokio::test]
pub(super) async fn require_auth_time_never_invents_an_authentication_timestamp() {
    let user_oid = Uuid::new_v4();
    let user = test_user(user_oid);
    let service =
        fixtures::build_token_service(Arc::new(MockClientAuthorizationRepository::new()), user_oid);
    let mut metadata = test_metadata(None, None);
    metadata.require_auth_time = Some(true);
    let client = OpenIdConnectClient::new(
        test_client(Uuid::new_v4()),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap();
    let issuer = "https://identity.example.com".parse().unwrap();

    assert!(
        service
            .sign_id_token(SignIdTokenInput {
                key_id: "unused",
                private_key_pem: "unused",
                alg: "RS256".parse().unwrap(),
                issuer: &issuer,
                audience: "client",
                client: &client,
                user: &user,
                scope: "openid",
                nonce: None,
                auth_time: None,
                acr: None,
                amr: &[],
                access_token: None,
                protected_session_id: None,
            })
            .await
            .is_err()
    );
}

pub(super) fn key_data_algorithm(key: &Key) -> String {
    match &key.data {
        KeyData::Asymmetric(data) => data
            .certificate
            .clone()
            .unwrap_or_else(|| "RS256".to_owned()),
        KeyData::Symmetric(_) => "RS256".to_owned(),
    }
}

pub(super) fn user_info_service_with_key(
    repo: Arc<MockClientAuthorizationRepository>,
    key: Key,
    user_oid: Uuid,
) -> UserInfoService {
    UserInfoService::new(
        Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
        }),
        Arc::new(InMemoryClientRepository),
        Arc::new(cred_repo_with(vec![])),
        repo,
        Arc::new(AsymmetricKeyService::new(
            Arc::new(key_repo_with_keys(vec![key])),
            Arc::new(TestAsymmetricKeyGenerator),
            test_key_jwk_generator(),
            None,
        )),
        provider_service(),
    )
}

pub(super) fn test_user(user_oid: Uuid) -> User {
    User {
        oid: UserOid(user_oid),
        email: "alg@example.com".to_string(),
        email_normalized: "alg@example.com".to_string(),
        name: "Alg User".to_string(),
        name_normalized: "alg user".to_string(),
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
        theme: None,
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

#[test]
pub(super) fn expected_at_hash_uses_sha256_for_256_bit_algs() {
    let token = "access-token";
    let digest = Sha256::digest(token.as_bytes());

    assert_eq!(
        expected_at_hash_for_alg(token, "RS256"),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "PS256"),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "ES256K"),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    );
}

#[test]
pub(super) fn expected_at_hash_uses_sha384_for_384_bit_algs() {
    let token = "access-token";
    let digest = Sha384::digest(token.as_bytes());

    assert_eq!(
        expected_at_hash_for_alg(token, "RS384"),
        URL_SAFE_NO_PAD.encode(&digest[..24])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "PS384"),
        URL_SAFE_NO_PAD.encode(&digest[..24])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "ES384"),
        URL_SAFE_NO_PAD.encode(&digest[..24])
    );
}

#[test]
pub(super) fn expected_at_hash_uses_sha512_for_512_bit_and_eddsa_algs() {
    let token = "access-token";
    let digest = Sha512::digest(token.as_bytes());

    assert_eq!(
        expected_at_hash_for_alg(token, "RS512"),
        URL_SAFE_NO_PAD.encode(&digest[..32])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "PS512"),
        URL_SAFE_NO_PAD.encode(&digest[..32])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "EdDSA"),
        URL_SAFE_NO_PAD.encode(&digest[..32])
    );
}

#[test]
pub(super) fn key_jwk_binding_uses_ec_shape_for_es256_keys() {
    let key = key_for_algorithm("ES256");
    let binding = key_jwk_binding(&key, "ES256", Uuid::new_v4());
    let jwk = to_value(binding.jwk).unwrap();

    assert_eq!(jwk["kty"], json!("EC"));
    assert_eq!(jwk["crv"], json!("P-256"));
    assert_eq!(jwk["alg"], json!("ES256"));
    assert_eq!(jwk["use"], json!("sig"));
    assert!(jwk.get("x").is_some());
    assert!(jwk.get("y").is_some());
}

#[test]
pub(super) fn key_jwk_binding_uses_okp_shape_for_eddsa_keys() {
    let key = key_for_algorithm("EdDSA");
    let binding = key_jwk_binding(&key, "EdDSA", Uuid::new_v4());
    let jwk = to_value(binding.jwk).unwrap();

    assert_eq!(jwk["kty"], json!("OKP"));
    assert_eq!(jwk["crv"], json!("Ed25519"));
    assert_eq!(jwk["alg"], json!("EdDSA"));
    assert_eq!(jwk["use"], json!("sig"));
    assert!(jwk.get("x").is_some());
}
