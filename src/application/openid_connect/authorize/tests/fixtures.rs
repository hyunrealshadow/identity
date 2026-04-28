use super::*;

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
                initialized_at: Some(chrono::Utc::now()),
            }),
        },
    )))
}

pub(super) struct MissingClientRepository;

#[derive(Default)]
pub(super) struct InMemoryClientAuthorizationRepository {
    pub(super) records: Mutex<HashMap<Uuid, ClientAuthorization>>,
}

pub(super) struct InMemoryLoginRepository;

#[derive(Default)]
pub(super) struct InMemoryCredentialRepository {
    pub(super) credentials: Mutex<Vec<OpenIdConnectCredential>>,
}

#[async_trait]
impl ClientAuthorizationRepository for InMemoryClientAuthorizationRepository {
    async fn create(
        &self,
        client_oid: Uuid,
        type_: ClientAuthorizationType,
        data: serde_json::Value,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
        let record = ClientAuthorization {
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
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError> {
        Ok(self.records.lock().unwrap().get(&oid).cloned())
    }

    async fn revoke_access_tokens_for_authorization_code(
        &self,
        _authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        Ok(())
    }

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientAuthorizationRepositoryError> {
        if let Some(record) = self.records.lock().unwrap().get_mut(&oid) {
            record.revoked_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

#[async_trait]
impl LoginRepository for InMemoryLoginRepository {
    async fn find_by_oid(&self, _oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        Ok(None)
    }

    async fn create_pending(
        &self,
        _client_oid: Uuid,
        _client_authorization_oid: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        Ok(Login {
            oid: Uuid::new_v4(),
            client_oid: _client_oid,
            client_authorization_oid: _client_authorization_oid,
            user_oid: None,
            status: LoginStatus::CREATED.to_string(),
            failed_attempts: 0,
            created_at: chrono::Utc::now(),
            acr: None,
            requested_acr: requested_acr.map(str::to_owned),
        })
    }

    async fn bind_user(
        &self,
        login_oid: Uuid,
        user_oid: Uuid,
        status: &str,
    ) -> Result<Login, LoginRepositoryError> {
        Ok(Login {
            oid: login_oid,
            client_oid: Uuid::new_v4(),
            client_authorization_oid: Uuid::new_v4(),
            user_oid: Some(user_oid),
            status: status.to_string(),
            failed_attempts: 0,
            created_at: chrono::Utc::now(),
            acr: None,
            requested_acr: None,
        })
    }

    async fn update_status(
        &self,
        _login_oid: Uuid,
        _status: &str,
        _session_oid: Option<Uuid>,
        _acr: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        Ok(())
    }

    async fn increment_failed_attempts(
        &self,
        _login_oid: Uuid,
        _failure_reason: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        Ok(())
    }
}

#[async_trait]
impl OpenIdConnectCredentialRepository for InMemoryCredentialRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        Ok(self
            .credentials
            .lock()
            .unwrap()
            .iter()
            .find(|item| item.oid == oid)
            .cloned())
    }

    async fn find_by_client_oid_and_type(
        &self,
        client_oid: Uuid,
        type_: OpenIdConnectCredentialType,
    ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        Ok(self
            .credentials
            .lock()
            .unwrap()
            .iter()
            .filter(|item| item.client_oid == client_oid && item.r#type == type_)
            .cloned()
            .collect())
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for MissingClientRepository {
    async fn find_by_oid(
        &self,
        _oid: Uuid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        Ok(None)
    }
}

pub(super) struct FoundClientRepository;

pub(super) struct RequestUriClientRepository {
    pub(super) request_uris: Vec<Url>,
}

pub(super) struct ScopedClientRepository {
    pub(super) assigned_scopes: Vec<String>,
}

pub(super) const TEST_CLIENT_ID: Uuid = Uuid::nil();

#[async_trait]
impl OpenIdConnectClientRepository for FoundClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
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
                    token_endpoint_auth_method: None,
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

#[async_trait]
impl OpenIdConnectClientRepository for ScopedClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
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
                    token_endpoint_auth_method: None,
                    token_endpoint_auth_signing_alg: None,
                    default_max_age: None,
                    require_auth_time: None,
                    default_acr_values: None,
                    initiate_login_uri: None,
                    request_uris: None,
                    skip_consent: false,
                },
                self.assigned_scopes.clone(),
            )
            .unwrap(),
        ))
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for RequestUriClientRepository {
    async fn find_by_oid(
        &self,
        oid: Uuid,
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
                    token_endpoint_auth_method: None,
                    token_endpoint_auth_signing_alg: None,
                    default_max_age: None,
                    require_auth_time: None,
                    default_acr_values: None,
                    initiate_login_uri: None,
                    request_uris: Some(self.request_uris.clone()),
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

pub(super) struct MockKeyRepository;

#[async_trait]
impl KeyRepository for MockKeyRepository {
    async fn find_by_oid(&self, _oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
        Ok(None)
    }

    async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        Ok(vec![])
    }

    async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        let raw_key = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
        Ok(vec![Key {
            oid: KeyOid::from(Uuid::new_v4()),
            r#type: KeyType::Symmetric,
            data: KeyData::Symmetric(SymmetricKeyData {
                key: raw_key,
                algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
            }),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }])
    }

    async fn create(
        &self,
        _key_type: KeyType,
        _data: &KeyData,
        _expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<Key, KeyRepositoryError> {
        unimplemented!()
    }

    async fn update_certificate_by_oid(
        &self,
        _oid: KeyOid,
        _certificate_pem: &str,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        unimplemented!()
    }

    async fn revoke_by_oid(
        &self,
        _oid: KeyOid,
        _revoked_at: chrono::DateTime<Utc>,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        unimplemented!()
    }
}

pub(super) fn test_data_protector() -> Arc<dyn DataProtector> {
    Arc::new(DataProtectorImpl::new(Arc::new(MockKeyRepository)))
}

pub(super) fn build_test_service(
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    login_repo: Arc<dyn LoginRepository>,
) -> AuthorizeService {
    AuthorizeService::new(
        client_repo,
        credential_repo,
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        login_repo,
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_data_protector(),
    )
}

pub(super) fn params(scope: &str) -> AuthorizationRequestParams {
    AuthorizationRequestParams {
        response_type: "code".to_string(),
        client_id: TEST_CLIENT_ID.to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: scope.to_string(),
        state: "state123".to_string(),
        nonce: None,
        display: None,
        prompt: None,
        max_age: None,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    }
}

pub(super) fn empty_optional_params() -> AuthorizationRequestParams {
    AuthorizationRequestParams {
        state: "state123".to_string(),
        ..params("openid profile")
    }
}

pub(super) fn signing_keypair() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    (
        rsa.private_key_to_pem().unwrap(),
        rsa.public_key_to_pem().unwrap(),
    )
}

pub(super) fn authorize_service_with_public_key(public_key: Vec<u8>) -> AuthorizeService {
    let credential_repo = InMemoryCredentialRepository {
        credentials: Mutex::new(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: TEST_CLIENT_ID,
            r#type: OpenIdConnectCredentialType::ClientPublicKey,
            hint: "request_object".to_string(),
            data: OpenIdConnectCredentialData::ClientPublicKey {
                public_key: String::from_utf8(public_key).unwrap(),
            },
            expires_at: chrono::Utc::now(),
            revoked_at: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
        }]),
    };

    AuthorizeService::new(
        Arc::new(FoundClientRepository),
        Arc::new(credential_repo),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_data_protector(),
    )
}

pub(super) fn authorize_service_with_request_uri(request_uri: &str) -> AuthorizeService {
    AuthorizeService::new(
        Arc::new(RequestUriClientRepository {
            request_uris: vec![Url::parse(request_uri).unwrap()],
        }),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryClientAuthorizationRepository::default()),
        Arc::new(InMemoryLoginRepository),
        Arc::new(StubUserRepository),
        Arc::new(StubKeyRepository),
        provider_service(),
        test_data_protector(),
    )
}

pub(super) async fn spawn_chunked_response_server(
    chunks: Vec<Vec<u8>>,
    keep_open_for: Duration,
) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
                )
                .await
                .unwrap();

        for chunk in chunks {
            stream
                .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(&chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
        }

        tokio::time::sleep(keep_open_for).await;
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

pub(super) async fn spawn_redirect_response_server(_location: &str) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let location = format!("http://{address}/final.jwt");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

pub(super) fn signed_request_object(
    private_key: &[u8],
    fields: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    for (name, value) in fields {
        payload.set_claim(name, Some(value)).unwrap();
    }

    let signer = RS256.signer_from_pem(private_key).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

pub(super) struct StubUserRepository;

#[async_trait]
impl UserRepository for StubUserRepository {
    async fn find_by_oid(&self, _oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        Ok(None)
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

pub(super) struct StubKeyRepository;

#[async_trait]
impl KeyRepository for StubKeyRepository {
    async fn find_by_oid(&self, _oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
        Ok(None)
    }

    async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        Ok(vec![])
    }

    async fn list_available_symmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
        Ok(vec![])
    }

    async fn create(
        &self,
        _key_type: KeyType,
        _data: &KeyData,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Key, KeyRepositoryError> {
        unimplemented!()
    }

    async fn update_certificate_by_oid(
        &self,
        _oid: KeyOid,
        _certificate_pem: &str,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        unimplemented!()
    }

    async fn revoke_by_oid(
        &self,
        _oid: KeyOid,
        _revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<Key>, KeyRepositoryError> {
        unimplemented!()
    }
}
