use super::*;
pub(super) use crate::openid_connect::tests::fixtures::mocks::{
    MockClientAuthorizationRepository, mock_client_auth_repo,
};
use crate::openid_connect::tests::fixtures::mocks::{
    MockKeyJwkRepository, MockKeyRepository, MockOpenIdConnectCredentialRepository,
};
use identity_domain::auth::SessionOid;

mod clients;

pub(super) use clients::{
    AuthMethodClientRepository, InMemoryClientRepository, PublicFlowClientRepository,
};

pub(super) const CLIENT_SECRET_JWT_SECRET: &str =
    "client-secret-jwt-secret-64-bytes-minimum-for-hs384-and-hs512";

pub(super) struct InMemoryDataProtector;

impl InMemoryDataProtector {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

pub(super) fn signing_algorithm_detector() -> Arc<dyn SigningAlgorithmDetector> {
    Arc::new(InMemorySigningAlgorithmDetector)
}

struct InMemorySigningAlgorithmDetector;

impl SigningAlgorithmDetector for InMemorySigningAlgorithmDetector {
    fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm> {
        let KeyData::Asymmetric(data) = &key.data else {
            return vec![];
        };

        if let Some(algorithm) = data
            .certificate
            .as_deref()
            .and_then(|value| value.parse().ok())
        {
            return vec![algorithm];
        }

        let pem = data.private_key.as_bytes();
        [
            (
                JwaSigningAlgorithm::Ps256,
                PS256.signer_from_pem(pem).is_ok(),
            ),
            (
                preferred_rsa_algorithm(pem),
                RS256.signer_from_pem(pem).is_ok(),
            ),
            (
                JwaSigningAlgorithm::Es256,
                ES256.signer_from_pem(pem).is_ok(),
            ),
            (
                JwaSigningAlgorithm::Es384,
                ES384.signer_from_pem(pem).is_ok(),
            ),
            (
                JwaSigningAlgorithm::Es512,
                ES512.signer_from_pem(pem).is_ok(),
            ),
            (
                JwaSigningAlgorithm::Es256k,
                ES256K.signer_from_pem(pem).is_ok(),
            ),
            (
                JwaSigningAlgorithm::EdDsa,
                EdDSA.signer_from_pem(pem).is_ok(),
            ),
        ]
        .into_iter()
        .filter_map(|(algorithm, supported)| supported.then_some(algorithm))
        .collect()
    }
}

fn preferred_rsa_algorithm(pem: &[u8]) -> JwaSigningAlgorithm {
    let Ok(key) = openssl::pkey::PKey::private_key_from_pem(pem) else {
        return JwaSigningAlgorithm::Rs256;
    };
    let Ok(rsa) = key.rsa() else {
        return JwaSigningAlgorithm::Rs256;
    };
    let bits = rsa.size() * 8;
    if bits >= 4096 {
        JwaSigningAlgorithm::Rs512
    } else if bits >= 3072 {
        JwaSigningAlgorithm::Rs384
    } else {
        JwaSigningAlgorithm::Rs256
    }
}

#[async_trait::async_trait]
impl crate::data_protection::DataProtector for InMemoryDataProtector {
    async fn protect(
        &self,
        _purpose: &str,
        plaintext: &[u8],
    ) -> Result<String, identity_domain::data_protection::DataProtectionError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        Ok(STANDARD.encode(plaintext))
    }

    async fn unprotect(
        &self,
        _purpose: &str,
        token: &str,
    ) -> Result<Vec<u8>, identity_domain::data_protection::DataProtectionError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD.decode(token).map_err(|_| {
            identity_domain::data_protection::DataProtectionError::InvalidProtectedPayload
        })
    }
}

pub(super) struct StaticInstallationProvider {
    pub(super) value: Arc<InstallationState>,
}

impl SettingProvider<InstallationSetting> for StaticInstallationProvider {
    fn current_value(&self) -> Arc<InstallationState> {
        self.value.clone()
    }
}

pub(super) fn provider_service() -> Arc<OpenIdProviderService> {
    Arc::new(OpenIdProviderService::new(Arc::new(
        StaticInstallationProvider {
            value: Arc::new(InstallationState {
                initialized: true,
                domain: Some("https://identity.example.com".to_string()),
                first_user_oid: Some(Uuid::new_v4()),
                first_key_oid: Some(Uuid::new_v4()),
                initialized_at: Some(Utc::now()),
            }),
        },
    )))
}

pub(super) fn key_repo_with_keys(keys: Vec<Key>) -> MockKeyRepository {
    let mut mock = MockKeyRepository::new();
    let k = keys.clone();
    mock.expect_find_by_oid()
        .returning(move |oid| Ok(k.iter().find(|key| key.oid == oid).cloned()));
    let k = keys.clone();
    mock.expect_list_available_asymmetric()
        .returning(move || Ok(k.clone()));
    let k = keys;
    mock.expect_list_available_symmetric()
        .returning(move || Ok(k.clone()));
    mock
}

pub(super) fn jwk_repo_with_bindings(bindings: Vec<KeyJwk>) -> MockKeyJwkRepository {
    let mut mock = MockKeyJwkRepository::new();
    let b = bindings.clone();
    mock.expect_list_active().returning(move || Ok(b.clone()));
    let b = bindings;
    mock.expect_find_active_by_key_oid_and_algorithm()
        .returning(move |oid, alg| {
            Ok(b.iter()
                .find(|b| b.key_oid == oid && b.algorithm == alg)
                .cloned())
        });
    mock
}

pub(super) struct InMemoryUserRepository {
    pub(super) user: User,
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn find_by_identifier(&self, _identifier: &str) -> Result<User, UserRepositoryError> {
        Ok(self.user.clone())
    }

    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        Ok((self.user.oid == oid).then_some(self.user.clone()))
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

pub(super) fn cred_repo_with(
    credentials: Vec<OpenIdConnectCredential>,
) -> MockOpenIdConnectCredentialRepository {
    let mut mock = MockOpenIdConnectCredentialRepository::new();
    mock.expect_find_by_client_oid_and_type()
        .returning(move |_, _| Ok(credentials.clone()));
    mock
}

pub(super) fn build_token_service(
    repo: Arc<MockClientAuthorizationRepository>,
    user_oid: Uuid,
) -> TokenService {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let key = Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: public_key.clone(),
            private_key,
            certificate: None,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());

    TokenService::new(
        repo,
        Arc::new(key_repo_with_keys(vec![key.clone()])),
        Arc::new(jwk_repo_with_bindings(vec![binding])),
        Arc::new(InMemoryUserRepository {
            user: User {
                oid: UserOid(user_oid),
                email: "a@example.com".to_string(),
                email_normalized: "a@example.com".to_string(),
                name: "A".to_string(),
                name_normalized: "a".to_string(),
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
        Arc::new(cred_repo_with(vec![
            OpenIdConnectCredential {
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
            },
            OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientPublicKey,
                hint: "private_key_jwt".to_string(),
                data: OpenIdConnectCredentialData::ClientPublicKey {
                    public_key,
                    jwk: None,
                },
                expires_at: Utc::now() + chrono::Duration::days(1),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            },
        ])),
        provider_service(),
        signing_algorithm_detector(),
        InMemoryDataProtector::new(),
    )
}

pub(super) fn build_token_service_with_auth_method(method: &'static str) -> TokenService {
    build_token_service_with_auth_method_and_alg(method, None)
}

pub(super) fn build_token_service_with_auth_method_and_alg(
    method: &'static str,
    signing_alg: Option<&'static str>,
) -> TokenService {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let key = Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: public_key.clone(),
            private_key,
            certificate: None,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    };
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());

    TokenService::new(
        repo,
        Arc::new(key_repo_with_keys(vec![key])),
        Arc::new(jwk_repo_with_bindings(vec![binding])),
        Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
        }),
        Arc::new(AuthMethodClientRepository {
            method,
            signing_alg,
        }),
        Arc::new(cred_repo_with(vec![
            OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientSecret,
                hint: "token".to_string(),
                data: OpenIdConnectCredentialData::ClientSecret {
                    secret: CLIENT_SECRET_JWT_SECRET.to_string(),
                },
                expires_at: Utc::now() + chrono::Duration::days(1),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            },
            OpenIdConnectCredential {
                oid: Uuid::new_v4(),
                client_oid: Uuid::nil(),
                r#type: OpenIdConnectCredentialType::ClientPublicKey,
                hint: "private_key_jwt".to_string(),
                data: OpenIdConnectCredentialData::ClientPublicKey {
                    public_key,
                    jwk: None,
                },
                expires_at: Utc::now() + chrono::Duration::days(1),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            },
        ])),
        provider_service(),
        signing_algorithm_detector(),
        InMemoryDataProtector::new(),
    )
}

pub(super) fn build_client_assertion_with_algorithm(
    private_key_pem: &str,
    alg: &str,
    client_id: &str,
    audience: &str,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    let now = std::time::SystemTime::now();
    payload.set_issuer(client_id);
    payload.set_subject(client_id);
    payload.set_audience(vec![audience]);
    payload.set_issued_at(&now);
    payload.set_expires_at(&(now + std::time::Duration::from_secs(300)));
    payload.set_jwt_id(Uuid::new_v4().to_string());

    match alg {
        "RS256" => jwt::encode_with_signer(
            &payload,
            &header,
            &*RS256.signer_from_pem(private_key_pem.as_bytes()).unwrap(),
        )
        .unwrap(),
        "ES256" => jwt::encode_with_signer(
            &payload,
            &header,
            &*ES256.signer_from_pem(private_key_pem.as_bytes()).unwrap(),
        )
        .unwrap(),
        "EdDSA" => jwt::encode_with_signer(
            &payload,
            &header,
            &*EdDSA.signer_from_pem(private_key_pem.as_bytes()).unwrap(),
        )
        .unwrap(),
        other => panic!("unsupported test alg: {other}"),
    }
}

pub(super) fn build_client_secret_assertion(
    secret: &str,
    client_id: &str,
    audience: &str,
) -> String {
    build_client_secret_assertion_with_algorithm(secret, "HS256", client_id, audience)
}

pub(super) fn build_client_secret_assertion_with_algorithm(
    secret: &str,
    alg: &str,
    client_id: &str,
    audience: &str,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    let now = std::time::SystemTime::now();
    payload.set_issuer(client_id);
    payload.set_subject(client_id);
    payload.set_audience(vec![audience]);
    payload.set_issued_at(&now);
    payload.set_expires_at(&(now + std::time::Duration::from_secs(300)));
    payload.set_jwt_id(Uuid::new_v4().to_string());

    match alg {
        "HS256" => jwt::encode_with_signer(
            &payload,
            &header,
            &*HS256.signer_from_bytes(secret.as_bytes()).unwrap(),
        )
        .unwrap(),
        "HS384" => jwt::encode_with_signer(
            &payload,
            &header,
            &*HS384.signer_from_bytes(secret.as_bytes()).unwrap(),
        )
        .unwrap(),
        "HS512" => jwt::encode_with_signer(
            &payload,
            &header,
            &*HS512.signer_from_bytes(secret.as_bytes()).unwrap(),
        )
        .unwrap(),
        other => panic!("unsupported test alg: {other}"),
    }
}
