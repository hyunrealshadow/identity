use super::*;

pub(super) struct InMemoryDataProtector;

impl InMemoryDataProtector {
    pub(super) fn new() -> Arc<Self> {
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
pub(super) struct InMemoryClientRequestRepository {
    pub(super) records: Mutex<HashMap<Uuid, ClientRequest>>,
}

pub(super) struct InMemoryClientRepository;

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
                vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                    "offline_access".to_string(),
                ],
            )
            .unwrap(),
        ))
    }
}

pub(super) struct InMemoryCredentialRepository {
    pub(super) credentials: Vec<OpenIdConnectCredential>,
}

#[async_trait]
impl OpenIdConnectCredentialRepository for InMemoryCredentialRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
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

pub(super) struct InMemoryKeyRepository {
    pub(super) keys: Vec<Key>,
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

pub(super) fn build_token_service(
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
