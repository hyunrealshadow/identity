use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jws::{ES256, ES256K, ES384, ES512, EdDSA, JwsHeader, RS256, RS384, RS512},
    jwt,
    jwt::JwtPayload,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::application::data_protection::DataProtector;

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use chrono::Utc;
    use josekit::{
        jws::{ES256, EdDSA, JwsHeader, RS256},
        jwt,
        jwt::JwtPayload,
    };
    use openssl::rsa::Rsa;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{AuthorizationCodeGrantParams, RefreshTokenGrantParams, TokenService, verify_pkce};
    use crate::{
        application::{
            openid_connect::provider::OpenIdProviderService, setting::runtime::SettingProvider,
        },
        domain::{
            client::model::{Client, ClientOid, ClientProtocol},
            client_request::{
                AuthorizationCodeData, ClientRequest, ClientRequestRepository,
                ClientRequestRepositoryError, ClientRequestType,
            },
            key::generator::AsymmetricKeyGenerator,
            key::{
                Key, KeyData, KeyOid, KeyType, material::AsymmetricKeyData,
                repository::KeyRepository,
            },
            openid_connect::{
                OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientRepository,
                OpenIdConnectClientRepositoryError, OpenIdConnectCredential,
                OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
                OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
                model::claim::JwtClaimNames,
            },
            setting::installation::{InstallationSetting, InstallationState},
            user::{
                User, UserOid,
                repository::{UserRepository, UserRepositoryError},
            },
        },
        infrastructure::crypto::key::AsymmetricKeyGeneratorImpl,
    };

    struct InMemoryDataProtector;

    impl InMemoryDataProtector {
        fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    #[async_trait::async_trait]
    impl crate::application::data_protection::DataProtector for InMemoryDataProtector {
        async fn protect(
            &self,
            _purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, crate::domain::data_protection::DataProtectionError> {
            use base64::{Engine, engine::general_purpose::STANDARD};
            Ok(STANDARD.encode(plaintext))
        }

        async fn unprotect(
            &self,
            _purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, crate::domain::data_protection::DataProtectionError> {
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.decode(token).map_err(|_| {
                crate::domain::data_protection::DataProtectionError::InvalidProtectedPayload
            })
        }
    }

    #[derive(Default)]
    struct InMemoryClientRequestRepository {
        records: Mutex<HashMap<Uuid, ClientRequest>>,
    }

    struct InMemoryClientRepository;

    #[async_trait]
    impl OpenIdConnectClientRepository for InMemoryClientRepository {
        async fn find_by_oid(
            &self,
            oid: ClientOid,
        ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
            Ok(Some(
                OpenIdConnectClient::new(
                    Client {
                        oid,
                        protocol: ClientProtocol::OpenIdConnect,
                        name: "Example RP".to_string(),
                        names: vec![],
                        description: None,
                        created_at: Utc::now(),
                        updated_at: None,
                    },
                    OpenIdConnectClientMetadata {
                        redirect_uris: Some(vec![
                            url::Url::parse("https://client.example.com/callback").unwrap(),
                        ]),
                        post_logout_redirect_uris: None,
                        response_types: None,
                        grant_types: None,
                        application_type: None,
                        contacts: None,
                        logo_uri: None,
                        client_uri: None,
                        policy_uri: None,
                        tos_uri: None,
                        sector_identifier_uri: None,
                        subject_type: None,
                        id_token_signed_response_alg: None,
                        id_token_encrypted_response_alg: None,
                        id_token_encrypted_response_enc: None,
                        userinfo_signed_response_alg: None,
                        userinfo_encrypted_response_alg: None,
                        userinfo_encrypted_response_enc: None,
                        request_object_signing_alg: None,
                        request_object_encryption_alg: None,
                        request_object_encryption_enc: None,
                        token_endpoint_auth_method: Some("client_secret_basic".to_string()),
                        token_endpoint_auth_signing_alg: None,
                        default_max_age: None,
                        require_auth_time: None,
                        default_acr_values: None,
                        initiate_login_uri: None,
                        request_uris: None,
                        skip_consent: false,
                    },
                )
                .unwrap(),
            ))
        }
    }

    struct InMemoryCredentialRepository {
        credentials: Vec<OpenIdConnectCredential>,
    }

    #[async_trait]
    impl OpenIdConnectCredentialRepository for InMemoryCredentialRepository {
        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>
        {
            Ok(self
                .credentials
                .iter()
                .find(|item| item.oid == oid)
                .cloned())
        }

        async fn find_by_client_oid_and_type(
            &self,
            client_oid: ClientOid,
            type_: OpenIdConnectCredentialType,
        ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
            Ok(self
                .credentials
                .iter()
                .filter(|item| item.client_oid == client_oid && item.r#type == type_)
                .cloned()
                .collect())
        }
    }

    struct StaticInstallationProvider {
        value: Arc<InstallationState>,
    }

    impl SettingProvider<InstallationSetting> for StaticInstallationProvider {
        fn current_value(&self) -> Arc<InstallationState> {
            self.value.clone()
        }
    }

    fn provider_service() -> Arc<OpenIdProviderService> {
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

    struct InMemoryKeyRepository {
        keys: Vec<Key>,
    }

    #[async_trait]
    impl KeyRepository for InMemoryKeyRepository {
        async fn find_by_oid(
            &self,
            oid: KeyOid,
        ) -> Result<Option<Key>, crate::domain::key::repository::KeyRepositoryError> {
            Ok(self.keys.iter().find(|key| key.oid == oid).cloned())
        }

        async fn list_available_asymmetric(
            &self,
        ) -> Result<Vec<Key>, crate::domain::key::repository::KeyRepositoryError> {
            Ok(self.keys.clone())
        }

        async fn list_available_symmetric(
            &self,
        ) -> Result<Vec<Key>, crate::domain::key::repository::KeyRepositoryError> {
            Ok(self.keys.clone())
        }

        async fn create(
            &self,
            _key_type: KeyType,
            _data: &KeyData,
            _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        ) -> Result<Key, crate::domain::key::repository::KeyRepositoryError> {
            unreachable!()
        }

        async fn update_certificate_by_oid(
            &self,
            _oid: KeyOid,
            _certificate_pem: &str,
        ) -> Result<Option<Key>, crate::domain::key::repository::KeyRepositoryError> {
            unreachable!()
        }

        async fn revoke_by_oid(
            &self,
            _oid: KeyOid,
            _revoked_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<Option<Key>, crate::domain::key::repository::KeyRepositoryError> {
            unreachable!()
        }
    }

    struct InMemoryUserRepository {
        user: User,
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

        async fn reset_failed_attempts(
            &self,
            _user_oid: UserOid,
        ) -> Result<(), UserRepositoryError> {
            Ok(())
        }
    }

    fn build_token_service(
        repo: Arc<InMemoryClientRequestRepository>,
        user_oid: Uuid,
    ) -> TokenService {
        let rsa = Rsa::generate(2048).unwrap();
        let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
        let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();

        TokenService::new(
            repo,
            Arc::new(InMemoryKeyRepository {
                keys: vec![Key {
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
                }],
            }),
            Arc::new(InMemoryUserRepository {
                user: User {
                    oid: UserOid(user_oid),
                    email: "a@example.com".to_string(),
                    email_normalized: "a@example.com".to_string(),
                    name: "A".to_string(),
                    name_normalized: "a".to_string(),
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
                credentials: vec![
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
                        data: OpenIdConnectCredentialData::ClientPublicKey { public_key },
                        expires_at: Utc::now() + chrono::Duration::days(1),
                        revoked_at: None,
                        created_at: Utc::now(),
                        updated_at: None,
                    },
                ],
            }),
            provider_service(),
            InMemoryDataProtector::new(),
        )
    }

    fn build_client_assertion_with_algorithm(
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
        payload.set_jwt_id(&Uuid::new_v4().to_string());

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

    #[async_trait]
    impl ClientRequestRepository for InMemoryClientRequestRepository {
        async fn create(
            &self,
            client_oid: ClientOid,
            type_: ClientRequestType,
            data: serde_json::Value,
            expires_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<ClientRequest, ClientRequestRepositoryError> {
            let record = ClientRequest {
                oid: Uuid::new_v4(),
                client_oid,
                type_,
                data,
                expires_at,
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: None,
            };
            self.records
                .lock()
                .unwrap()
                .insert(record.oid, record.clone());
            Ok(record)
        }

        async fn find_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError> {
            Ok(self.records.lock().unwrap().get(&oid).cloned())
        }

        async fn find_refresh_token_by_token(
            &self,
            token: &str,
        ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .values()
                .find(|record| {
                    serde_json::from_value::<crate::domain::client_request::RefreshTokenData>(
                        record.data.clone(),
                    )
                    .map(|data| data.token == token)
                    .unwrap_or(false)
                })
                .cloned())
        }

        async fn revoke(&self, oid: Uuid) -> Result<(), ClientRequestRepositoryError> {
            if let Some(record) = self.records.lock().unwrap().get_mut(&oid) {
                record.revoked_at = Some(Utc::now());
            }
            Ok(())
        }
    }

    #[test]
    fn verify_pkce_accepts_matching_s256_verifier() {
        let verifier = "abc123verifier";
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);

        assert!(verify_pkce(Some(&challenge), Some("S256"), Some(verifier)).is_ok());
    }

    #[test]
    fn verify_pkce_rejects_mismatched_plain_verifier() {
        let result = verify_pkce(Some("expected"), Some("plain"), Some("actual"));
        assert!(result.is_err());
    }

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
            .authenticate_client_secret_basic(
                "00000000-0000-0000-0000-000000000000",
                "wrong-secret",
            )
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
        let (access_payload, _) =
            jwt::decode_with_verifier(&result.access_token, &verifier).unwrap();
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
}

use crate::{
    application::{
        error::{AppError, codes::token::TokenErrorCode},
        openid_connect::provider::OpenIdProviderService,
    },
    domain::{
        client_request::{
            AuthorizationCodeData, ClientRequestRepository, ClientRequestType, RefreshTokenData,
        },
        key::{KeyData, repository::KeyRepository},
        openid_connect::{
            OpenIdConnectClientRepository, OpenIdConnectCredentialData,
            OpenIdConnectCredentialRepository, OpenIdConnectCredentialType,
            model::claim::{JwtClaimNames, JwtTokenType, StandardScopes, TokenUseValues},
        },
        user::{UserOid, repository::UserRepository},
    },
};

#[derive(Debug, Clone)]
pub struct AuthorizationCodeGrantParams {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenGrantParams {
    pub grant_type: String,
    pub refresh_token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: String,
}

pub struct TokenService {
    client_request_repo: Arc<dyn ClientRequestRepository>,
    key_repo: Arc<dyn KeyRepository>,
    user_repo: Arc<dyn UserRepository>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    provider_service: Arc<OpenIdProviderService>,
    data_protector: Arc<dyn DataProtector>,
}

impl TokenService {
    pub fn new(
        client_request_repo: Arc<dyn ClientRequestRepository>,
        key_repo: Arc<dyn KeyRepository>,
        user_repo: Arc<dyn UserRepository>,
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        provider_service: Arc<OpenIdProviderService>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            client_request_repo,
            key_repo,
            user_repo,
            client_repo,
            credential_repo,
            provider_service,
            data_protector,
        }
    }

    pub async fn exchange_authorization_code(
        &self,
        params: AuthorizationCodeGrantParams,
    ) -> Result<TokenResponse, AppError> {
        if params.grant_type != "authorization_code" {
            return Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType));
        }

        let client_id = params
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientIdRequired))?;
        let authenticated_client_oid = self
            .authenticate_client(
                client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type.as_deref(),
                params.client_assertion.as_deref(),
            )
            .await?;

        let code_oid_bytes = self
            .data_protector
            .unprotect("authorization-code", &params.code)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::AuthCodeNotFound).with_source(error)
            })?;
        let code_oid = Uuid::from_slice(&code_oid_bytes).map_err(|error| {
            AppError::from_code(TokenErrorCode::AuthCodeNotFound).with_source(error)
        })?;

        let record = self
            .client_request_repo
            .find_by_oid(code_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CodeLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeNotFound))?;

        if record.type_ != ClientRequestType::AuthorizationCode {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeNotFound));
        }

        if record.client_oid != authenticated_client_oid {
            return Err(AppError::from_code(TokenErrorCode::CodeClientMismatch));
        }

        if record.revoked_at.is_some() || record.expires_at <= chrono::Utc::now() {
            return Err(AppError::from_code(TokenErrorCode::AuthCodeInvalid));
        }

        let data: AuthorizationCodeData =
            serde_json::from_value(record.data.clone()).map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeCodeFailed).with_source(error)
            })?;

        let redirect_uri = params
            .redirect_uri
            .as_deref()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RedirectUriMismatch))?;
        if redirect_uri != data.redirect_uri {
            return Err(AppError::from_code(TokenErrorCode::RedirectUriMismatch));
        }

        let verifier = params.code_verifier.as_deref();

        verify_pkce(
            data.code_challenge.as_deref(),
            data.code_challenge_method.as_deref(),
            verifier,
        )?;

        let user_oid = Uuid::parse_str(&data.user_oid).map_err(|error| {
            AppError::from_code(TokenErrorCode::StoredUserOidInvalid).with_source(error)
        })?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::UserLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AuthCodeUserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key().await?;
        let audience = params
            .client_id
            .clone()
            .unwrap_or_else(|| record.client_oid.to_string());
        let client_id_str = record.client_oid.to_string();
        let access_token = self.sign_access_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            &audience,
            &client_id_str,
            &user_oid,
            &data.session_oid,
            &data.scope,
        )?;
        let id_token = if data.scope.split_whitespace().any(|scope| scope == "openid") {
            Some(self.sign_id_token(
                &signing_key_id,
                &signing_key_pem,
                &signing_alg,
                &issuer,
                &audience,
                &user,
                data.nonce.as_deref(),
                data.auth_time,
                data.acr.as_deref(),
                &data.scope,
            )?)
        } else {
            None
        };
        let refresh_token = if data
            .scope
            .split_whitespace()
            .any(|scope| scope == "offline_access")
        {
            let refresh_token = self.sign_refresh_token(
                &signing_key_id,
                &signing_key_pem,
                &signing_alg,
                &issuer,
                &audience,
                &user_oid,
            )?;
            self.store_refresh_token(
                record.client_oid,
                &refresh_token,
                &data.scope,
                &data.user_oid,
                &data.session_oid,
                None,
            )
            .await?;
            Some(refresh_token)
        } else {
            None
        };

        self.client_request_repo
            .revoke(record.oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeCodeFailed).with_source(error)
            })?;

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: data.scope,
        })
    }

    pub async fn exchange_refresh_token(
        &self,
        params: RefreshTokenGrantParams,
    ) -> Result<TokenResponse, AppError> {
        if params.grant_type != "refresh_token" {
            return Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType));
        }

        let client_id = params
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientIdRequired))?;
        let authenticated_client_oid = self
            .authenticate_client(
                client_id,
                params.client_secret.as_deref(),
                params.client_assertion_type.as_deref(),
                params.client_assertion.as_deref(),
            )
            .await?;

        let refresh_record = self
            .client_request_repo
            .find_refresh_token_by_token(&params.refresh_token)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RefreshTokenLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenNotFound))?;
        if refresh_record.revoked_at.is_some() || refresh_record.expires_at <= chrono::Utc::now() {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        }
        let refresh_data: RefreshTokenData = serde_json::from_value(refresh_record.data.clone())
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeRefreshFailed).with_source(error)
            })?;
        let refresh_claims = self.verify_refresh_token(&params.refresh_token).await?;
        let subject = refresh_claims
            .subject()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenSubMissing))?
            .to_string();
        let token_use = refresh_claims
            .claim(JwtClaimNames::TOKEN_USE)
            .and_then(|value| value.as_str())
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenUseMissing))?;
        if token_use != TokenUseValues::REFRESH_TOKEN {
            return Err(AppError::from_code(TokenErrorCode::RefreshTokenUseInvalid));
        }

        let audience_matches = refresh_claims
            .claim(JwtClaimNames::AUD)
            .and_then(|value| {
                value.as_str().map(|aud| aud == client_id).or_else(|| {
                    value.as_array().map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str())
                            .any(|aud| aud == client_id)
                    })
                })
            })
            .unwrap_or(false);
        if !audience_matches
            || authenticated_client_oid.to_string() != client_id
            || refresh_record.client_oid != authenticated_client_oid
        {
            return Err(AppError::from_code(
                TokenErrorCode::RefreshTokenClientMismatch,
            ));
        }

        let user_oid = Uuid::parse_str(&subject).map_err(|error| {
            AppError::from_code(TokenErrorCode::RefreshTokenSubInvalid).with_source(error)
        })?;
        let user = self
            .user_repo
            .find_by_oid(UserOid(user_oid))
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::UserLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::RefreshTokenUserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key().await?;
        let scope = refresh_data.scope.clone();
        let access_token = self.sign_access_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            client_id,
            client_id,
            &user_oid,
            &refresh_data.session_oid,
            &scope,
        )?;
        let id_token = Some(self.sign_id_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            client_id,
            &user,
            None,
            None,
            None,
            &scope,
        )?);
        let refresh_token = Some(self.sign_refresh_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            client_id,
            &user_oid,
        )?);
        self.client_request_repo
            .revoke(refresh_record.oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::RevokeRefreshFailed).with_source(error)
            })?;
        if let Some(refresh_token_value) = &refresh_token {
            self.store_refresh_token(
                authenticated_client_oid,
                refresh_token_value,
                &scope,
                &subject,
                &refresh_data.session_oid,
                Some(params.refresh_token.as_str()),
            )
            .await?;
        }

        Ok(TokenResponse {
            access_token,
            id_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope,
        })
    }

    async fn load_signing_key(&self) -> Result<(String, String, String), AppError> {
        let keys = self
            .key_repo
            .list_available_asymmetric()
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
            })?;

        for key in keys {
            if let KeyData::Asymmetric(data) = key.data {
                let pem = data.private_key.as_bytes();
                if RS256.signer_from_pem(pem).is_ok() {
                    return Ok((
                        Uuid::from(key.oid).to_string(),
                        data.private_key,
                        "RS256".to_string(),
                    ));
                }
                if ES256.signer_from_pem(pem).is_ok() {
                    return Ok((
                        Uuid::from(key.oid).to_string(),
                        data.private_key,
                        "ES256".to_string(),
                    ));
                }
            }
        }

        Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))
    }

    async fn authenticate_client_secret_basic(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        let valid = credentials.into_iter().any(|credential| {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = &credential.data {
                constant_time_compare(secret.as_bytes(), client_secret.as_bytes())
            } else {
                false
            }
        });

        if !valid {
            return Err(AppError::from_code(
                TokenErrorCode::ClientCredentialsInvalid,
            ));
        }

        Ok(client.client().oid)
    }

    async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion_type: Option<&str>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        if let (Some(assertion_type), Some(assertion)) = (client_assertion_type, client_assertion) {
            if assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
                return self
                    .authenticate_private_key_jwt(client_id, assertion)
                    .await;
            }
        }

        let client_secret =
            client_secret.ok_or_else(|| AppError::from_code(TokenErrorCode::ClientAuthRequired))?;
        self.authenticate_client_secret_basic(client_id, client_secret)
            .await
    }

    async fn authenticate_private_key_jwt(
        &self,
        client_id: &str,
        assertion: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let payload = self.verify_client_assertion(&client, assertion).await?;
        let issuer = self.provider_service.issuer()?;

        let iss = payload
            .claim(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionIssMissing))?;
        let sub = payload
            .subject()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionSubMissing))?;
        if iss != client_id || sub != client_id {
            return Err(AppError::from_code(TokenErrorCode::AssertionIssSubMismatch));
        }

        let audience_matches = payload
            .claim(JwtClaimNames::AUD)
            .and_then(|value| {
                value
                    .as_str()
                    .map(|aud| aud == issuer.as_str())
                    .or_else(|| {
                        value.as_array().map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str())
                                .any(|aud| aud == issuer.as_str())
                        })
                    })
            })
            .unwrap_or(false);
        if !audience_matches {
            return Err(AppError::from_code(TokenErrorCode::AssertionAudMismatch));
        }

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = payload
            .claim(JwtClaimNames::EXP)
            .and_then(|value| value.as_i64())
        {
            if exp <= now {
                return Err(AppError::from_code(TokenErrorCode::AssertionExpired));
            }
        }
        if let Some(nbf) = payload
            .claim(JwtClaimNames::NBF)
            .and_then(|value| value.as_i64())
        {
            if nbf > now {
                return Err(AppError::from_code(TokenErrorCode::AssertionNotYetValid));
            }
        }

        Ok(client.client().oid)
    }

    async fn verify_client_assertion(
        &self,
        client: &crate::domain::openid_connect::OpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion).map_err(|error| {
            AppError::from_code(TokenErrorCode::AssertionHeaderInvalid).with_source(error)
        })?;
        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientPublicKey { public_key } = credential.data {
                if let Ok(payload) =
                    decode_assertion_with_alg(algorithm, assertion, public_key.as_bytes())
                {
                    return Ok(payload);
                }
            }
        }

        let jwks_credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientJsonWebKeySet,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;
        for credential in jwks_credentials {
            if let OpenIdConnectCredentialData::ClientJsonWebKeySet { public_keys, .. } =
                credential.data
            {
                for public_key in public_keys {
                    if let Ok(payload) =
                        decode_assertion_with_alg(algorithm, assertion, public_key.as_bytes())
                    {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed))
    }

    async fn verify_refresh_token(&self, raw: &str) -> Result<JwtPayload, AppError> {
        let keys = self
            .key_repo
            .list_available_asymmetric()
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::KeyListFailed).with_source(error)
            })?;

        for key in keys {
            if let KeyData::Asymmetric(data) = key.data {
                let verifier = match RS256.verifier_from_pem(data.public_key.as_bytes()) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if let Ok((payload, _)) = jwt::decode_with_verifier(raw, &verifier) {
                    return Ok(payload);
                }
            }
        }

        Err(AppError::from_code(
            TokenErrorCode::RefreshTokenVerifyFailed,
        ))
    }

    fn sign_access_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        client_id: &str,
        user_oid: &Uuid,
        session_oid: &str,
        scope: &str,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(&user_oid.to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        payload.set_jwt_id(&Uuid::new_v4().to_string());
        payload
            .set_claim(JwtClaimNames::CLIENT_ID, Some(serde_json::json!(client_id)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SCOPE, Some(serde_json::json!(scope)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(JwtClaimNames::SID, Some(serde_json::json!(session_oid)))
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;
        payload
            .set_claim(
                JwtClaimNames::TOKEN_USE,
                Some(serde_json::json!(TokenUseValues::ACCESS_TOKEN)),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
            })?;

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(RS256.signer_from_pem(private_key_pem.as_bytes()).map_err(
                |error| {
                    AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
                },
            )?),
            _ => Box::new(
                ES256
                    .signer_from_pem(private_key_pem.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignAccessTokenFailed)
                            .with_source(error)
                    })?,
            ),
        };
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignAccessTokenFailed).with_source(error)
        })
    }

    fn sign_id_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        user: &crate::domain::user::User,
        nonce: Option<&str>,
        auth_time: Option<i64>,
        acr: Option<&str>,
        scope: &str,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(&Uuid::from(user.oid).to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
        let scopes: Vec<&str> = scope.split_whitespace().collect();
        if scopes.contains(&StandardScopes::EMAIL) {
            payload
                .set_claim(JwtClaimNames::EMAIL, Some(serde_json::json!(user.email)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
            payload
                .set_claim(
                    JwtClaimNames::EMAIL_VERIFIED,
                    Some(serde_json::json!(user.email_verified)),
                )
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if scopes.contains(&StandardScopes::PROFILE) {
            payload
                .set_claim(JwtClaimNames::NAME, Some(serde_json::json!(user.name)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(nonce) = nonce {
            payload
                .set_claim(JwtClaimNames::NONCE, Some(serde_json::json!(nonce)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(auth_time) = auth_time {
            payload
                .set_claim(JwtClaimNames::AUTH_TIME, Some(serde_json::json!(auth_time)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }
        if let Some(acr) = acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                })?;
        }

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(RS256.signer_from_pem(private_key_pem.as_bytes()).map_err(
                |error| AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error),
            )?),
            _ => Box::new(
                ES256
                    .signer_from_pem(private_key_pem.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
                    })?,
            ),
        };
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignIdTokenFailed).with_source(error)
        })
    }

    fn sign_refresh_token(
        &self,
        key_id: &str,
        private_key_pem: &str,
        alg: &str,
        issuer: &url::Url,
        audience: &str,
        user_oid: &Uuid,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_subject(&user_oid.to_string());
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(30 * 24 * 60 * 60)));
        payload
            .set_claim(
                JwtClaimNames::TOKEN_USE,
                Some(serde_json::json!(TokenUseValues::REFRESH_TOKEN)),
            )
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
            })?;

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(RS256.signer_from_pem(private_key_pem.as_bytes()).map_err(
                |error| {
                    AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
                },
            )?),
            _ => Box::new(
                ES256
                    .signer_from_pem(private_key_pem.as_bytes())
                    .map_err(|error| {
                        AppError::from_code(TokenErrorCode::SignRefreshTokenFailed)
                            .with_source(error)
                    })?,
            ),
        };
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|error| {
            AppError::from_code(TokenErrorCode::SignRefreshTokenFailed).with_source(error)
        })
    }

    async fn store_refresh_token(
        &self,
        client_oid: Uuid,
        token: &str,
        scope: &str,
        user_oid: &str,
        session_oid: &str,
        rotated_from: Option<&str>,
    ) -> Result<(), AppError> {
        let data = serde_json::to_value(RefreshTokenData {
            token: token.to_string(),
            scope: scope.to_string(),
            user_oid: user_oid.to_string(),
            session_oid: session_oid.to_string(),
            rotated_from: rotated_from.map(str::to_string),
        })
        .map_err(|error| {
            AppError::from_code(TokenErrorCode::SerializeRefreshFailed).with_source(error)
        })?;

        self.client_request_repo
            .create(
                client_oid,
                ClientRequestType::RefreshToken,
                data,
                chrono::Utc::now() + chrono::Duration::days(30),
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::StoreRefreshFailed).with_source(error)
            })?;

        Ok(())
    }

    #[cfg(test)]
    async fn build_client_assertion_for_test(&self, client_id: &str) -> String {
        let issuer = self.provider_service.issuer().unwrap();
        let (key_id, private_key, _alg) = self.load_signing_key().await.unwrap();
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(&key_id);

        let mut payload = JwtPayload::new();
        let now = std::time::SystemTime::now();
        payload.set_issuer(client_id);
        payload.set_subject(client_id);
        payload.set_audience(vec![issuer.as_str()]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + std::time::Duration::from_secs(300)));
        payload.set_jwt_id(&Uuid::new_v4().to_string());

        let signer = RS256.signer_from_pem(private_key.as_bytes()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }
}

fn decode_assertion_with_alg(
    alg: &str,
    assertion: &str,
    public_key_pem: &[u8],
) -> Result<JwtPayload, AppError> {
    match alg {
        "RS256" => decode_with_verifier(assertion, RS256.verifier_from_pem(public_key_pem)),
        "RS384" => decode_with_verifier(assertion, RS384.verifier_from_pem(public_key_pem)),
        "RS512" => decode_with_verifier(assertion, RS512.verifier_from_pem(public_key_pem)),
        "ES256" => decode_with_verifier(assertion, ES256.verifier_from_pem(public_key_pem)),
        "ES384" => decode_with_verifier(assertion, ES384.verifier_from_pem(public_key_pem)),
        "ES512" => decode_with_verifier(assertion, ES512.verifier_from_pem(public_key_pem)),
        "ES256K" => decode_with_verifier(assertion, ES256K.verifier_from_pem(public_key_pem)),
        "EdDSA" => decode_with_verifier(assertion, EdDSA.verifier_from_pem(public_key_pem)),
        _ => Err(AppError::from_code(TokenErrorCode::AssertionAlgUnsupported)),
    }
}

fn decode_with_verifier<V>(
    assertion: &str,
    verifier: Result<V, josekit::JoseError>,
) -> Result<JwtPayload, AppError>
where
    V: josekit::jws::JwsVerifier,
{
    let verifier = verifier.map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionKeyInvalid).with_source(error)
    })?;
    let (payload, _) = jwt::decode_with_verifier(assertion, &verifier).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })?;
    Ok(payload)
}

fn verify_pkce(
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    code_verifier: Option<&str>,
) -> Result<(), AppError> {
    let Some(code_challenge) = code_challenge else {
        return Ok(());
    };

    let Some(code_verifier) = code_verifier else {
        return Err(AppError::from_code(TokenErrorCode::CodeVerifierRequired));
    };

    let method = code_challenge_method.unwrap_or("plain");
    let computed = match method {
        "plain" => code_verifier.to_string(),
        "S256" => {
            let digest = Sha256::digest(code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
        _ => {
            return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported));
        }
    };

    if computed != code_challenge {
        return Err(AppError::from_code(TokenErrorCode::PkceVerifierMismatch));
    }

    Ok(())
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
