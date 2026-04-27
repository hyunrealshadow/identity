use std::sync::Arc;

use josekit::jws::{ES256, ES256K, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512};
use url::Url;

use crate::{
    application::{
        error::{AppError, codes::provider::ProviderErrorCode},
        setting::runtime::SettingProvider,
    },
    domain::{
        key::{Key, KeyData, repository::KeyRepository},
        openid_connect::{
            OpenIdProviderMetadata,
            model::claim::{JwtClaimNames, StandardScopes},
        },
        setting::installation::{InstallationSetting, InstallationState},
    },
};

#[derive(Debug, Clone)]
pub struct OpenIdProviderCapabilities {
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub acr_values_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub id_token_encryption_alg_values_supported: Vec<String>,
    pub id_token_encryption_enc_values_supported: Vec<String>,
    pub userinfo_signing_alg_values_supported: Vec<String>,
    pub userinfo_encryption_alg_values_supported: Vec<String>,
    pub userinfo_encryption_enc_values_supported: Vec<String>,
    pub request_object_signing_alg_values_supported: Vec<String>,
    pub request_object_encryption_alg_values_supported: Vec<String>,
    pub request_object_encryption_enc_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub display_values_supported: Vec<String>,
    pub claim_types_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub claims_locales_supported: Vec<String>,
    pub ui_locales_supported: Vec<String>,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
}

impl Default for OpenIdProviderCapabilities {
    fn default() -> Self {
        Self {
            scopes_supported: vec![
                StandardScopes::OPENID.to_owned(),
                StandardScopes::PROFILE.to_owned(),
                StandardScopes::EMAIL.to_owned(),
                StandardScopes::ADDRESS.to_owned(),
                StandardScopes::PHONE.to_owned(),
                StandardScopes::OFFLINE_ACCESS.to_owned(),
            ],
            response_types_supported: vec![
                "code".to_owned(),
                "id_token".to_owned(),
                "token id_token".to_owned(),
            ],
            response_modes_supported: vec!["query".to_owned(), "fragment".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "implicit".to_owned(),
                "refresh_token".to_owned(),
            ],
            acr_values_supported: vec!["1".to_owned()],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["ES256".to_owned()],
            id_token_encryption_alg_values_supported: vec![],
            id_token_encryption_enc_values_supported: vec![],
            userinfo_signing_alg_values_supported: vec![],
            userinfo_encryption_alg_values_supported: vec![],
            userinfo_encryption_enc_values_supported: vec![],
            request_object_signing_alg_values_supported: vec![
                "none".to_owned(),
                "RS256".to_owned(),
            ],
            request_object_encryption_alg_values_supported: vec![],
            request_object_encryption_enc_values_supported: vec![],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_owned(),
                "client_secret_post".to_owned(),
                "private_key_jwt".to_owned(),
            ],
            token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_owned()],
            display_values_supported: vec!["page".to_owned()],
            claim_types_supported: vec!["normal".to_owned()],
            claims_supported: vec![
                JwtClaimNames::SUB.to_owned(),
                JwtClaimNames::ISS.to_owned(),
                JwtClaimNames::AUTH_TIME.to_owned(),
                JwtClaimNames::ACR.to_owned(),
                JwtClaimNames::NAME.to_owned(),
                JwtClaimNames::GIVEN_NAME.to_owned(),
                JwtClaimNames::FAMILY_NAME.to_owned(),
                JwtClaimNames::MIDDLE_NAME.to_owned(),
                JwtClaimNames::NICKNAME.to_owned(),
                JwtClaimNames::PROFILE.to_owned(),
                JwtClaimNames::PICTURE.to_owned(),
                JwtClaimNames::WEBSITE.to_owned(),
                JwtClaimNames::GENDER.to_owned(),
                JwtClaimNames::BIRTHDATE.to_owned(),
                JwtClaimNames::ZONEINFO.to_owned(),
                JwtClaimNames::LOCALE.to_owned(),
                JwtClaimNames::UPDATED_AT.to_owned(),
                JwtClaimNames::PREFERRED_USERNAME.to_owned(),
                JwtClaimNames::EMAIL.to_owned(),
                JwtClaimNames::EMAIL_VERIFIED.to_owned(),
                JwtClaimNames::PHONE_NUMBER.to_owned(),
                JwtClaimNames::PHONE_NUMBER_VERIFIED.to_owned(),
                JwtClaimNames::ADDRESS.to_owned(),
            ],
            claims_locales_supported: vec![],
            ui_locales_supported: vec![],
            claims_parameter_supported: true,
            request_parameter_supported: true,
            request_uri_parameter_supported: true,
            require_request_uri_registration: false,
        }
    }
}

#[derive(Clone)]
pub struct OpenIdProviderService {
    installation_setting: Arc<dyn SettingProvider<InstallationSetting>>,
    capabilities: OpenIdProviderCapabilities,
    key_repo: Option<Arc<dyn KeyRepository>>,
}

fn detect_id_token_signing_algorithms(keys: &[Key]) -> Vec<String> {
    let mut algos = std::collections::BTreeSet::new();
    for key in keys {
        if let KeyData::Asymmetric(ref data) = key.data {
            let pem = data.private_key.as_bytes();
            if RS256.signer_from_pem(pem).is_ok() {
                algos.insert("RS256".to_owned());
            }
            if RS384.signer_from_pem(pem).is_ok() {
                algos.insert("RS384".to_owned());
            }
            if RS512.signer_from_pem(pem).is_ok() {
                algos.insert("RS512".to_owned());
            }
            if PS256.signer_from_pem(pem).is_ok() {
                algos.insert("PS256".to_owned());
            }
            if PS384.signer_from_pem(pem).is_ok() {
                algos.insert("PS384".to_owned());
            }
            if PS512.signer_from_pem(pem).is_ok() {
                algos.insert("PS512".to_owned());
            }
            if ES256.signer_from_pem(pem).is_ok() {
                algos.insert("ES256".to_owned());
            }
            if ES384.signer_from_pem(pem).is_ok() {
                algos.insert("ES384".to_owned());
            }
            if ES512.signer_from_pem(pem).is_ok() {
                algos.insert("ES512".to_owned());
            }
            if ES256K.signer_from_pem(pem).is_ok() {
                algos.insert("ES256K".to_owned());
            }
            if EdDSA.signer_from_pem(pem).is_ok() {
                algos.insert("EdDSA".to_owned());
            }
        }
    }
    algos.into_iter().collect()
}

impl OpenIdProviderService {
    pub fn new(installation_setting: Arc<dyn SettingProvider<InstallationSetting>>) -> Self {
        Self {
            installation_setting,
            capabilities: OpenIdProviderCapabilities::default(),
            key_repo: None,
        }
    }

    pub fn with_capabilities(
        installation_setting: Arc<dyn SettingProvider<InstallationSetting>>,
        capabilities: OpenIdProviderCapabilities,
    ) -> Self {
        Self {
            installation_setting,
            capabilities,
            key_repo: None,
        }
    }

    pub fn with_key_repo(mut self, key_repo: Arc<dyn KeyRepository>) -> Self {
        self.key_repo = Some(key_repo);
        self
    }

    pub fn issuer(&self) -> Result<Url, AppError> {
        let installation = self.installation_setting.current_value();
        canonical_issuer(installation.as_ref())
    }

    pub async fn discovery_metadata(&self) -> Result<OpenIdProviderMetadata, AppError> {
        let issuer = self.issuer()?;

        let id_token_algos = self.compute_id_token_signing_algos().await?;

        Ok(OpenIdProviderMetadata {
            issuer: issuer.clone(),
            authorization_endpoint: endpoint_url(&issuer, "/oauth2/authorize")?,
            token_endpoint: Some(endpoint_url(&issuer, "/oauth2/token")?),
            userinfo_endpoint: Some(endpoint_url(&issuer, "/oauth2/userinfo")?),
            jwks_uri: endpoint_url(&issuer, "/.well-known/keys")?,
            registration_endpoint: None,
            scopes_supported: non_empty(self.capabilities.scopes_supported.clone()),
            response_types_supported: self.capabilities.response_types_supported.clone(),
            response_modes_supported: non_empty(self.capabilities.response_modes_supported.clone()),
            grant_types_supported: non_empty(self.capabilities.grant_types_supported.clone()),
            acr_values_supported: non_empty(self.capabilities.acr_values_supported.clone()),
            subject_types_supported: self.capabilities.subject_types_supported.clone(),
            id_token_signing_alg_values_supported: id_token_algos,
            id_token_encryption_alg_values_supported: non_empty(
                self.capabilities
                    .id_token_encryption_alg_values_supported
                    .clone(),
            ),
            id_token_encryption_enc_values_supported: non_empty(
                self.capabilities
                    .id_token_encryption_enc_values_supported
                    .clone(),
            ),
            userinfo_signing_alg_values_supported: non_empty(
                self.capabilities
                    .userinfo_signing_alg_values_supported
                    .clone(),
            ),
            userinfo_encryption_alg_values_supported: non_empty(
                self.capabilities
                    .userinfo_encryption_alg_values_supported
                    .clone(),
            ),
            userinfo_encryption_enc_values_supported: non_empty(
                self.capabilities
                    .userinfo_encryption_enc_values_supported
                    .clone(),
            ),
            request_object_signing_alg_values_supported: non_empty(
                self.capabilities
                    .request_object_signing_alg_values_supported
                    .clone(),
            ),
            request_object_encryption_alg_values_supported: non_empty(
                self.capabilities
                    .request_object_encryption_alg_values_supported
                    .clone(),
            ),
            request_object_encryption_enc_values_supported: non_empty(
                self.capabilities
                    .request_object_encryption_enc_values_supported
                    .clone(),
            ),
            token_endpoint_auth_methods_supported: non_empty(
                self.capabilities
                    .token_endpoint_auth_methods_supported
                    .clone(),
            ),
            token_endpoint_auth_signing_alg_values_supported: non_empty(
                self.capabilities
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
            ),
            display_values_supported: non_empty(self.capabilities.display_values_supported.clone()),
            claim_types_supported: non_empty(self.capabilities.claim_types_supported.clone()),
            claims_supported: non_empty(self.capabilities.claims_supported.clone()),
            service_documentation: Some(endpoint_url(&issuer, "/docs/openid-connect")?),
            claims_locales_supported: non_empty(self.capabilities.claims_locales_supported.clone()),
            ui_locales_supported: non_empty(self.capabilities.ui_locales_supported.clone()),
            claims_parameter_supported: self.capabilities.claims_parameter_supported,
            request_parameter_supported: self.capabilities.request_parameter_supported,
            request_uri_parameter_supported: self.capabilities.request_uri_parameter_supported,
            require_request_uri_registration: self.capabilities.require_request_uri_registration,
            op_policy_uri: Some(endpoint_url(&issuer, "/policy")?),
            op_tos_uri: Some(endpoint_url(&issuer, "/terms")?),
            end_session_endpoint: None,
        })
    }

    async fn compute_id_token_signing_algos(&self) -> Result<Vec<String>, AppError> {
        match self.key_repo {
            Some(ref key_repo) => {
                let keys = key_repo
                    .list_available_asymmetric()
                    .await
                    .map_err(|error| {
                        AppError::from_code(ProviderErrorCode::KeyLookupFailed).with_source(error)
                    })?;
                let detected = detect_id_token_signing_algorithms(&keys);
                Ok(if detected.is_empty() {
                    self.capabilities
                        .id_token_signing_alg_values_supported
                        .clone()
                } else {
                    detected
                })
            }
            None => Ok(self
                .capabilities
                .id_token_signing_alg_values_supported
                .clone()),
        }
    }
}

fn non_empty(values: Vec<String>) -> Option<Vec<String>> {
    (!values.is_empty()).then_some(values)
}

fn endpoint_url(issuer: &Url, path: &str) -> Result<Url, AppError> {
    let base = issuer.as_str().trim_end_matches('/');
    Url::parse(&format!("{base}{path}")).map_err(|error| {
        AppError::from_code(ProviderErrorCode::IssuerUrlParseFailed).with_source(error)
    })
}

fn canonical_issuer(installation: &InstallationState) -> Result<Url, AppError> {
    if !installation.initialized {
        return Err(AppError::from_code(ProviderErrorCode::NotInitialized));
    }

    let raw = installation
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::from_code(ProviderErrorCode::DomainMissing))?;

    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };

    let mut issuer = Url::parse(&candidate).map_err(|error| {
        AppError::from_code(ProviderErrorCode::IssuerUrlParseFailed).with_source(error)
    })?;

    if issuer.scheme() != "https" {
        // In conformance/dev mode (feature flag) allow http for local testing.
        #[cfg(not(feature = "oidc-conformance"))]
        return Err(AppError::from_code(ProviderErrorCode::IssuerMustUseHttps));
    }

    if issuer.query().is_some() || issuer.fragment().is_some() {
        return Err(AppError::from_code(
            ProviderErrorCode::IssuerMustNotHaveQueryOrFragment,
        ));
    }

    let normalized_path = issuer.path().trim_end_matches('/').to_owned();
    issuer.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        &normalized_path
    });

    Ok(issuer)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use async_trait::async_trait;
    use chrono::Utc;
    use josekit::jwk::KeyPair;
    use serde_json::to_value;
    use uuid::Uuid;

    use super::OpenIdProviderService;
    use crate::{
        application::setting::runtime::CachedSetting,
        domain::{
            key::{
                Key, KeyData, KeyOid, KeyType,
                material::AsymmetricKeyData,
                repository::{KeyRepository, KeyRepositoryError},
            },
            setting::{
                installation::{InstallationSetting, InstallationState},
                model::{SettingDefinition, SettingEntry},
                repository::{SettingRepository, SettingRepositoryError},
            },
        },
    };

    #[derive(Clone)]
    struct TestSettingRepo {
        value: Arc<RwLock<serde_json::Value>>,
    }

    #[async_trait]
    impl SettingRepository for TestSettingRepo {
        async fn get<S>(&self) -> Result<Option<SettingEntry<S::Value>>, SettingRepositoryError>
        where
            S: SettingDefinition,
        {
            let value = self.value.read().unwrap().clone();
            let parsed =
                serde_json::from_value(value).map_err(SettingRepositoryError::Deserialize)?;

            Ok(Some(SettingEntry {
                oid: Uuid::new_v4().into(),
                key: S::KEY.to_owned(),
                value: parsed,
                created_at: Utc::now(),
                updated_at: None,
            }))
        }

        async fn upsert<S>(
            &self,
            value: &S::Value,
        ) -> Result<SettingEntry<S::Value>, SettingRepositoryError>
        where
            S: SettingDefinition,
        {
            let serialized = to_value(value).map_err(SettingRepositoryError::Serialize)?;
            *self.value.write().unwrap() = serialized;

            Ok(SettingEntry {
                oid: Uuid::new_v4().into(),
                key: S::KEY.to_owned(),
                value: value.clone(),
                created_at: Utc::now(),
                updated_at: None,
            })
        }
    }

    struct StaticKeyRepository {
        keys: Vec<Key>,
        fail_list: bool,
    }

    impl StaticKeyRepository {
        fn with_keys(keys: Vec<Key>) -> Arc<Self> {
            Arc::new(Self {
                keys,
                fail_list: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                keys: vec![],
                fail_list: true,
            })
        }
    }

    #[async_trait]
    impl KeyRepository for StaticKeyRepository {
        async fn find_by_oid(&self, _oid: KeyOid) -> Result<Option<Key>, KeyRepositoryError> {
            Ok(None)
        }

        async fn list_available_asymmetric(&self) -> Result<Vec<Key>, KeyRepositoryError> {
            if self.fail_list {
                return Err(KeyRepositoryError::ListAvailableFailed(
                    sea_orm::DbErr::Custom("boom".to_owned()),
                ));
            }

            Ok(self.keys.clone())
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

    fn make_asymmetric_key(private_key_pem: String) -> Key {
        Key {
            oid: KeyOid(Uuid::new_v4()),
            r#type: KeyType::Asymmetric,
            data: KeyData::Asymmetric(AsymmetricKeyData {
                public_key: String::new(),
                private_key: private_key_pem,
                certificate: None,
            }),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    fn generate_rsa_pem() -> String {
        let jwk = josekit::jwk::Jwk::generate_rsa_key(2048).unwrap();
        let key_pair = josekit::jwk::alg::rsa::RsaKeyPair::from_jwk(&jwk).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    fn generate_rsa_pss_pem(alg: &str) -> String {
        let (hash, salt_len) = match alg {
            "PS256" => (josekit::util::SHA_256, 32),
            "PS384" => (josekit::util::SHA_384, 48),
            "PS512" => (josekit::util::SHA_512, 64),
            other => panic!("unsupported RSA-PSS test alg: {other}"),
        };
        let key_pair =
            josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(2048, hash, hash, salt_len).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    fn generate_ec_p256_pem() -> String {
        let jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
        let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    fn generate_ec_p384_pem() -> String {
        let jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P384).unwrap();
        let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    fn generate_ec_p521_pem() -> String {
        let jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P521).unwrap();
        let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    fn generate_ec_secp256k1_pem() -> String {
        let jwk =
            josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
        let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    fn generate_ed25519_pem() -> String {
        let jwk =
            josekit::jwk::Jwk::generate_ed_key(josekit::jwk::alg::ed::EdCurve::Ed25519).unwrap();
        let key_pair = josekit::jwk::alg::ed::EdKeyPair::from_jwk(&jwk).unwrap();
        String::from_utf8(key_pair.to_pem_private_key()).unwrap()
    }

    #[tokio::test]
    async fn canonicalizes_plain_domain_to_https_issuer() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await;

        let issuer = service.issuer().unwrap();

        assert_eq!(issuer.as_str(), "https://identity.example.com/");
    }

    #[tokio::test]
    async fn assembles_discovery_document_from_issuer_and_capabilities() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com/issuer1/".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await;

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.issuer.as_str(),
            "https://identity.example.com/issuer1"
        );
        assert_eq!(
            metadata.authorization_endpoint.as_str(),
            "https://identity.example.com/issuer1/oauth2/authorize"
        );
        assert_eq!(
            metadata.jwks_uri.as_str(),
            "https://identity.example.com/issuer1/.well-known/keys"
        );
        assert!(metadata.end_session_endpoint.is_none());
        assert_eq!(
            metadata.response_types_supported,
            vec!["code", "id_token", "token id_token"]
        );
    }

    #[tokio::test]
    async fn default_discovery_advertises_supported_address_and_phone_claims() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await;

        let metadata = service.discovery_metadata().await.unwrap();
        let scopes = metadata.scopes_supported.unwrap();
        let claims = metadata.claims_supported.unwrap();

        assert!(scopes.iter().any(|scope| scope == "address"));
        assert!(scopes.iter().any(|scope| scope == "phone"));
        assert!(claims.iter().any(|claim| claim == "address"));
        assert!(claims.iter().any(|claim| claim == "phone_number"));
        assert!(claims.iter().any(|claim| claim == "phone_number_verified"));
    }

    #[tokio::test]
    async fn discovery_uses_rsa_key_repo_algorithm() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await
        .with_key_repo(StaticKeyRepository::with_keys(vec![make_asymmetric_key(
            generate_rsa_pem(),
        )]));

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            vec!["RS256".to_owned(), "RS384".to_owned(), "RS512".to_owned()]
        );
    }

    #[tokio::test]
    async fn discovery_uses_rsa_pss_key_repo_algorithm() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await
        .with_key_repo(StaticKeyRepository::with_keys(vec![
            make_asymmetric_key(generate_rsa_pss_pem("PS256")),
            make_asymmetric_key(generate_rsa_pss_pem("PS384")),
            make_asymmetric_key(generate_rsa_pss_pem("PS512")),
        ]));

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            vec!["PS256".to_owned(), "PS384".to_owned(), "PS512".to_owned()]
        );
    }

    #[tokio::test]
    async fn discovery_uses_ec_key_repo_algorithm() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await
        .with_key_repo(StaticKeyRepository::with_keys(vec![make_asymmetric_key(
            generate_ec_p256_pem(),
        )]));

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            vec!["ES256".to_owned()]
        );
    }

    #[tokio::test]
    async fn discovery_uses_all_detected_key_repo_algorithms() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await
        .with_key_repo(StaticKeyRepository::with_keys(vec![
            make_asymmetric_key(generate_rsa_pem()),
            make_asymmetric_key(generate_rsa_pss_pem("PS256")),
            make_asymmetric_key(generate_rsa_pss_pem("PS384")),
            make_asymmetric_key(generate_rsa_pss_pem("PS512")),
            make_asymmetric_key(generate_ec_p256_pem()),
            make_asymmetric_key(generate_ec_p384_pem()),
            make_asymmetric_key(generate_ec_p521_pem()),
            make_asymmetric_key(generate_ec_secp256k1_pem()),
            make_asymmetric_key(generate_ed25519_pem()),
        ]));

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            vec![
                "ES256".to_owned(),
                "ES256K".to_owned(),
                "ES384".to_owned(),
                "ES512".to_owned(),
                "EdDSA".to_owned(),
                "PS256".to_owned(),
                "PS384".to_owned(),
                "PS512".to_owned(),
                "RS256".to_owned(),
                "RS384".to_owned(),
                "RS512".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn discovery_falls_back_to_capabilities_when_key_repo_has_no_detected_algorithms() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await
        .with_key_repo(StaticKeyRepository::with_keys(vec![]));

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            vec!["ES256".to_owned()]
        );
    }

    #[tokio::test]
    async fn discovery_maps_key_repo_errors() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await
        .with_key_repo(StaticKeyRepository::failing());

        let error = service.discovery_metadata().await.unwrap_err();

        assert_eq!(error.code(), 20005);
    }

    impl OpenIdProviderService {
        async fn for_test(state: InstallationState) -> Self {
            let setting = CachedSetting::<InstallationSetting, _>::new(TestSettingRepo {
                value: Arc::new(RwLock::new(to_value(state).unwrap())),
            })
            .await
            .unwrap();

            Self::new(Arc::new(setting))
        }
    }

    mod detect_algorithms {
        use super::super::detect_id_token_signing_algorithms;
        use crate::domain::key::{
            Key, KeyData, KeyOid, KeyType,
            material::{AsymmetricKeyData, SymmetricKeyAlgorithm, SymmetricKeyData},
        };
        use chrono::Utc;
        use josekit::jwk::alg::{ec::EcCurve, ed::EdCurve};
        use josekit::jwk::{Jwk, KeyPair};
        use uuid::Uuid;

        fn make_asymmetric_key(private_key_pem: String) -> Key {
            Key {
                oid: KeyOid(Uuid::new_v4()),
                r#type: KeyType::Asymmetric,
                data: KeyData::Asymmetric(AsymmetricKeyData {
                    public_key: String::new(),
                    private_key: private_key_pem,
                    certificate: None,
                }),
                expires_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }
        }

        fn make_symmetric_key() -> Key {
            Key {
                oid: KeyOid(Uuid::new_v4()),
                r#type: KeyType::Symmetric,
                data: KeyData::Symmetric(SymmetricKeyData {
                    key: "dummy".to_owned(),
                    algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
                }),
                expires_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            }
        }

        fn generate_rsa_pem() -> String {
            let jwk = Jwk::generate_rsa_key(2048).unwrap();
            let key_pair = josekit::jwk::alg::rsa::RsaKeyPair::from_jwk(&jwk).unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        fn generate_rsa_pss_pem(alg: &str) -> String {
            let (hash, salt_len) = match alg {
                "PS256" => (josekit::util::SHA_256, 32),
                "PS384" => (josekit::util::SHA_384, 48),
                "PS512" => (josekit::util::SHA_512, 64),
                other => panic!("unsupported RSA-PSS test alg: {other}"),
            };
            let key_pair =
                josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(2048, hash, hash, salt_len)
                    .unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        fn generate_ec_p256_pem() -> String {
            let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
            let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        fn generate_ec_p384_pem() -> String {
            let jwk = Jwk::generate_ec_key(EcCurve::P384).unwrap();
            let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        fn generate_ec_p521_pem() -> String {
            let jwk = Jwk::generate_ec_key(EcCurve::P521).unwrap();
            let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        fn generate_ec_secp256k1_pem() -> String {
            let jwk = Jwk::generate_ec_key(EcCurve::Secp256k1).unwrap();
            let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        fn generate_ed25519_pem() -> String {
            let jwk = Jwk::generate_ed_key(EdCurve::Ed25519).unwrap();
            let key_pair = josekit::jwk::alg::ed::EdKeyPair::from_jwk(&jwk).unwrap();
            String::from_utf8(key_pair.to_pem_private_key()).unwrap()
        }

        #[test]
        fn empty_keys_returns_empty_vec() {
            let algos = detect_id_token_signing_algorithms(&[]);
            assert!(algos.is_empty());
        }

        #[test]
        fn symmetric_key_is_ignored() {
            let key = make_symmetric_key();
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert!(algos.is_empty());
        }

        #[test]
        fn rsa_key_detects_all_rs_variants() {
            let pem = generate_rsa_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert!(
                algos.contains(&"RS256".to_owned()),
                "expected RS256, got: {algos:?}"
            );
            assert!(
                algos.contains(&"RS384".to_owned()),
                "expected RS384, got: {algos:?}"
            );
            assert!(
                algos.contains(&"RS512".to_owned()),
                "expected RS512, got: {algos:?}"
            );
        }

        #[test]
        fn rsa_pss_keys_detect_ps_variants() {
            let keys = [
                make_asymmetric_key(generate_rsa_pss_pem("PS256")),
                make_asymmetric_key(generate_rsa_pss_pem("PS384")),
                make_asymmetric_key(generate_rsa_pss_pem("PS512")),
            ];
            let algos = detect_id_token_signing_algorithms(&keys);
            assert!(
                algos.contains(&"PS256".to_owned()),
                "expected PS256, got: {algos:?}"
            );
            assert!(
                algos.contains(&"PS384".to_owned()),
                "expected PS384, got: {algos:?}"
            );
            assert!(
                algos.contains(&"PS512".to_owned()),
                "expected PS512, got: {algos:?}"
            );
        }

        #[test]
        fn rsa_key_does_not_falsely_detect_ec_algorithms() {
            let pem = generate_rsa_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert!(!algos.contains(&"ES256".to_owned()));
            assert!(!algos.contains(&"ES256K".to_owned()));
            assert!(!algos.contains(&"EdDSA".to_owned()));
        }

        #[test]
        fn ec_p256_key_detects_es256() {
            let pem = generate_ec_p256_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert!(
                algos.contains(&"ES256".to_owned()),
                "expected ES256, got: {algos:?}"
            );
        }

        #[test]
        fn ec_p384_key_detects_es384() {
            let key = make_asymmetric_key(generate_ec_p384_pem());
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert_eq!(algos, vec!["ES384".to_owned()]);
        }

        #[test]
        fn ec_p521_key_detects_es512() {
            let key = make_asymmetric_key(generate_ec_p521_pem());
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert_eq!(algos, vec!["ES512".to_owned()]);
        }

        #[test]
        fn ec_secp256k1_key_detects_es256k() {
            let key = make_asymmetric_key(generate_ec_secp256k1_pem());
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert_eq!(algos, vec!["ES256K".to_owned()]);
        }

        #[test]
        fn ed25519_key_detects_eddsa() {
            let key = make_asymmetric_key(generate_ed25519_pem());
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert_eq!(algos, vec!["EdDSA".to_owned()]);
        }

        #[test]
        fn ec_p256_key_does_not_falsely_detect_rs_or_ed_algorithms() {
            let pem = generate_ec_p256_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key]);
            assert!(!algos.contains(&"RS256".to_owned()));
            assert!(!algos.contains(&"RS384".to_owned()));
            assert!(!algos.contains(&"EdDSA".to_owned()));
        }

        #[test]
        fn mixed_keys_detect_both_families() {
            let rsa_key = make_asymmetric_key(generate_rsa_pem());
            let ps_key = make_asymmetric_key(generate_rsa_pss_pem("PS256"));
            let ec_key = make_asymmetric_key(generate_ec_p256_pem());
            let algos = detect_id_token_signing_algorithms(&[rsa_key, ps_key, ec_key]);
            assert!(algos.contains(&"RS256".to_owned()));
            assert!(algos.contains(&"RS384".to_owned()));
            assert!(algos.contains(&"RS512".to_owned()));
            assert!(algos.contains(&"PS256".to_owned()));
            assert!(algos.contains(&"ES256".to_owned()));
        }
    }
}
