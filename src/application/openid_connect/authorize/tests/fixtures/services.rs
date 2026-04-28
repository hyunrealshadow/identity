use super::*;

pub(crate) struct StaticInstallationProvider {
    pub(crate) value: Arc<InstallationState>,
}

impl SettingProvider<InstallationSetting> for StaticInstallationProvider {
    fn current_value(&self) -> Arc<InstallationState> {
        self.value.clone()
    }
}

pub(crate) fn provider_service() -> Arc<OpenIdProviderService> {
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

pub(crate) struct MockKeyRepository;

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

pub(crate) struct StubUserRepository;

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

pub(crate) struct StubKeyRepository;

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

pub(crate) fn test_data_protector() -> Arc<dyn DataProtector> {
    Arc::new(DataProtectorImpl::new(Arc::new(MockKeyRepository)))
}

pub(crate) fn build_test_service(
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
