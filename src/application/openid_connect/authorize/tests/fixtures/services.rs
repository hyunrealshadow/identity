use super::*;
use crate::openid_connect::authorize::tests::fixtures::repositories::{
    ClientAuthorizationState, mock_client_auth_repo_with_state,
};
use crate::openid_connect::tests::fixtures::mocks::{
    MockKeyJwkRepository, MockKeyRepository as MockallKeyRepository,
    MockOpenIdConnectCredentialRepository, MockUserRepository,
};
use identity_domain::user::repository::UserRepositoryError;

pub(in crate::openid_connect) struct StaticInstallationProvider {
    pub(in crate::openid_connect) value: Arc<InstallationState>,
}

impl SettingProvider<InstallationSetting> for StaticInstallationProvider {
    fn current_value(&self) -> Arc<InstallationState> {
        self.value.clone()
    }
}

pub(in crate::openid_connect) fn provider_service() -> Arc<OpenIdProviderService> {
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

struct TestCipher;

impl DataProtectionCipher for TestCipher {
    fn encrypt(
        &self,
        _key: &[u8; DATA_PROTECTION_KEY_SIZE],
        plaintext: &[u8],
        _aad: &[u8],
    ) -> Result<([u8; 24], Vec<u8>), identity_domain::data_protection::DataProtectionError> {
        Ok(([0u8; 24], plaintext.to_vec()))
    }

    fn decrypt(
        &self,
        _key: &[u8; DATA_PROTECTION_KEY_SIZE],
        _nonce: &[u8; 24],
        ciphertext: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, identity_domain::data_protection::DataProtectionError> {
        Ok(ciphertext.to_vec())
    }
}

pub(in crate::openid_connect) fn test_signing_algorithm_detector()
-> Arc<dyn SigningAlgorithmDetector> {
    Arc::new(TestSigningAlgorithmDetector)
}

pub(in crate::openid_connect) fn test_data_protector() -> Arc<dyn DataProtector> {
    let mut key_repo = MockallKeyRepository::new();
    key_repo.expect_find_by_oid().returning(|_| Ok(None));
    key_repo
        .expect_list_available_asymmetric()
        .returning(|| Ok(vec![]));
    key_repo.expect_list_available_symmetric().returning(|| {
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
    });
    key_repo.expect_create().returning(|_, _, _| {
        Err(
            identity_domain::key::repository::KeyRepositoryError::CreateFailed(
                "not implemented in test fixture".into(),
            ),
        )
    });
    key_repo
        .expect_update_certificate_by_oid()
        .returning(|_, _| {
            Err(
                identity_domain::key::repository::KeyRepositoryError::UpdateFailed(
                    "not implemented in test fixture".into(),
                ),
            )
        });
    key_repo.expect_revoke_by_oid().returning(|_, _| {
        Err(
            identity_domain::key::repository::KeyRepositoryError::UpdateFailed(
                "not implemented in test fixture".into(),
            ),
        )
    });
    Arc::new(DataProtectorImpl::new(
        Arc::new(key_repo),
        Arc::new(TestCipher),
    ))
}

struct TestSigningAlgorithmDetector;

impl SigningAlgorithmDetector for TestSigningAlgorithmDetector {
    fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm> {
        match key.data {
            KeyData::Asymmetric(_) => vec![JwaSigningAlgorithm::Rs256],
            KeyData::Symmetric(_) => vec![],
        }
    }
}

pub(in crate::openid_connect) fn build_test_service(
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    login_repo: Arc<dyn LoginRepository>,
) -> AuthorizeService {
    let state = Arc::new(ClientAuthorizationState::default());
    let auth_repo = Arc::new(mock_client_auth_repo_with_state(state));
    AuthorizeService::new(AuthorizeServiceDependencies {
        client_repo,
        credential_repo,
        client_authorization_repo: auth_repo,
        login_repo,
        user_repo: Arc::new(stub_user_repo()),
        key_repo: Arc::new(stub_key_repo()),
        key_jwk_repo: Arc::new(MockKeyJwkRepository::new()),
        provider_service: provider_service(),
        signing_algorithm_detector: test_signing_algorithm_detector(),
        data_protector: test_data_protector(),
        http_client: crate::openid_connect::remote::test_http_client(),
    })
}

pub(in crate::openid_connect) fn stub_key_repo() -> MockallKeyRepository {
    let mut mock = MockallKeyRepository::new();
    mock.expect_find_by_oid().returning(|_| Ok(None));
    mock.expect_list_available_asymmetric()
        .returning(|| Ok(vec![]));
    mock.expect_list_available_symmetric()
        .returning(|| Ok(vec![]));
    mock
}

pub(in crate::openid_connect) fn stub_user_repo() -> MockUserRepository {
    let mut mock = MockUserRepository::new();
    mock.expect_find_by_oid().returning(|_| Ok(None));
    mock.expect_find_by_identifier()
        .returning(|_| Err(UserRepositoryError::UserNotFound));
    mock
}

pub(in crate::openid_connect) fn empty_cred_repo() -> MockOpenIdConnectCredentialRepository {
    let mut mock = MockOpenIdConnectCredentialRepository::new();
    mock.expect_find_by_client_oid_and_type()
        .returning(|_, _| Ok(vec![]));
    mock
}
