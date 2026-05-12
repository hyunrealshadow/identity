use std::sync::Arc;

use url::Url;

use crate::{
    application::{
        error::{AppError, codes::provider::ProviderErrorCode},
        setting::runtime::SettingProvider,
    },
    domain::{
        key::{JwaSigningAlgorithm, Key, KeyData, repository::KeyRepository},
        openid_connect::{
            OpenIdProviderMetadata, ResponseMode, SubjectType, TokenEndpointAuthMethod,
            model::claim::{JwtClaimNames, StandardScopes},
        },
        setting::installation::{InstallationSetting, InstallationState},
    },
};

#[derive(Debug, Clone)]
pub struct OpenIdProviderCapabilities {
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<ResponseMode>,
    pub grant_types_supported: Vec<String>,
    pub acr_values_supported: Vec<String>,
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub id_token_encryption_alg_values_supported: Vec<String>,
    pub id_token_encryption_enc_values_supported: Vec<String>,
    pub userinfo_signing_alg_values_supported: Vec<String>,
    pub userinfo_encryption_alg_values_supported: Vec<String>,
    pub userinfo_encryption_enc_values_supported: Vec<String>,
    pub request_object_signing_alg_values_supported: Vec<String>,
    pub request_object_encryption_alg_values_supported: Vec<String>,
    pub request_object_encryption_enc_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
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

pub trait SigningAlgorithmDetector: Send + Sync {
    fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm>;
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
                "id_token token".to_owned(),
                "code id_token".to_owned(),
                "code token".to_owned(),
                "code id_token token".to_owned(),
            ],
            response_modes_supported: vec![
                ResponseMode::Query,
                ResponseMode::Fragment,
                ResponseMode::FormPost,
            ],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "implicit".to_owned(),
                "refresh_token".to_owned(),
            ],
            acr_values_supported: vec!["1".to_owned()],
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            id_token_signing_alg_values_supported: vec!["ES256".to_owned()],
            id_token_encryption_alg_values_supported: vec![
                "RSA-OAEP".to_owned(),
                "RSA-OAEP-256".to_owned(),
                "ECDH-ES".to_owned(),
                "ECDH-ES+A128KW".to_owned(),
                "ECDH-ES+A256KW".to_owned(),
            ],
            id_token_encryption_enc_values_supported: vec![
                "A128CBC-HS256".to_owned(),
                "A256CBC-HS512".to_owned(),
                "A128GCM".to_owned(),
                "A256GCM".to_owned(),
            ],
            userinfo_signing_alg_values_supported: vec![],
            userinfo_encryption_alg_values_supported: vec![
                "RSA-OAEP".to_owned(),
                "RSA-OAEP-256".to_owned(),
                "ECDH-ES".to_owned(),
                "ECDH-ES+A128KW".to_owned(),
                "ECDH-ES+A256KW".to_owned(),
            ],
            userinfo_encryption_enc_values_supported: vec![
                "A128CBC-HS256".to_owned(),
                "A256CBC-HS512".to_owned(),
                "A128GCM".to_owned(),
                "A256GCM".to_owned(),
            ],
            request_object_signing_alg_values_supported:
                supported_request_object_signing_algorithms(),
            request_object_encryption_alg_values_supported: vec![
                "RSA-OAEP".to_owned(),
                "RSA-OAEP-256".to_owned(),
                "ECDH-ES".to_owned(),
                "ECDH-ES+A128KW".to_owned(),
                "ECDH-ES+A256KW".to_owned(),
            ],
            request_object_encryption_enc_values_supported: vec![
                "A128CBC-HS256".to_owned(),
                "A256CBC-HS512".to_owned(),
                "A128GCM".to_owned(),
                "A256GCM".to_owned(),
            ],
            token_endpoint_auth_methods_supported: vec![
                TokenEndpointAuthMethod::ClientSecretBasic,
                TokenEndpointAuthMethod::ClientSecretPost,
                TokenEndpointAuthMethod::ClientSecretJwt,
                TokenEndpointAuthMethod::PrivateKeyJwt,
            ],
            token_endpoint_auth_signing_alg_values_supported:
                supported_token_endpoint_auth_signing_algorithms(),
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

fn supported_request_object_signing_algorithms() -> Vec<String> {
    let mut algorithms = vec!["none".to_owned()];
    algorithms.extend(supported_asymmetric_jws_algorithms());
    algorithms
}

fn supported_token_endpoint_auth_signing_algorithms() -> Vec<String> {
    let mut algorithms = vec!["HS256".to_owned(), "HS384".to_owned(), "HS512".to_owned()];
    algorithms.extend(supported_asymmetric_jws_algorithms());
    algorithms
}

fn supported_asymmetric_jws_algorithms() -> Vec<String> {
    JwaSigningAlgorithm::all()
        .iter()
        .map(|algorithm| algorithm.as_str().to_owned())
        .collect()
}

#[derive(Clone)]
pub struct OpenIdProviderService {
    installation_setting: Arc<dyn SettingProvider<InstallationSetting>>,
    capabilities: OpenIdProviderCapabilities,
    key_repo: Option<Arc<dyn KeyRepository>>,
    signing_algorithm_detector: Option<Arc<dyn SigningAlgorithmDetector>>,
}

fn detect_id_token_signing_algorithms(
    keys: &[Key],
    detector: &dyn SigningAlgorithmDetector,
) -> Vec<String> {
    let mut algos = std::collections::BTreeSet::new();
    for key in keys {
        if let KeyData::Asymmetric(_) = key.data {
            algos.extend(
                detector
                    .detect(key)
                    .into_iter()
                    .map(|jwa| jwa.as_str().to_owned()),
            );
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
            signing_algorithm_detector: None,
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
            signing_algorithm_detector: None,
        }
    }

    pub fn with_key_repo(mut self, key_repo: Arc<dyn KeyRepository>) -> Self {
        self.key_repo = Some(key_repo);
        self
    }

    pub fn with_signing_algorithm_detector(
        mut self,
        detector: Arc<dyn SigningAlgorithmDetector>,
    ) -> Self {
        self.signing_algorithm_detector = Some(detector);
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
            response_modes_supported: non_empty(to_string_values(
                &self.capabilities.response_modes_supported,
            )),
            grant_types_supported: non_empty(self.capabilities.grant_types_supported.clone()),
            acr_values_supported: non_empty(self.capabilities.acr_values_supported.clone()),
            subject_types_supported: to_string_values(&self.capabilities.subject_types_supported),
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
            token_endpoint_auth_methods_supported: non_empty(to_string_values(
                &self.capabilities.token_endpoint_auth_methods_supported,
            )),
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
            end_session_endpoint: Some(endpoint_url(&issuer, "/oauth2/logout")?),
            check_session_iframe: Some(endpoint_url(&issuer, "/oauth2/check_session")?),
            frontchannel_logout_supported: Some(true),
            frontchannel_logout_session_supported: Some(true),
            backchannel_logout_supported: Some(true),
            backchannel_logout_session_supported: Some(true),
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
                let detected = self
                    .signing_algorithm_detector
                    .as_ref()
                    .map(|detector| detect_id_token_signing_algorithms(&keys, detector.as_ref()))
                    .unwrap_or_default();
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

fn to_string_values<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
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
    use serde_json::to_value;
    use uuid::Uuid;

    use super::{OpenIdProviderService, SigningAlgorithmDetector};
    use crate::{
        application::setting::runtime::CachedSetting,
        domain::{
            key::{
                JwaSigningAlgorithm, Key, KeyData, KeyOid, KeyType,
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

    struct TestSigningAlgorithmDetector;

    impl SigningAlgorithmDetector for TestSigningAlgorithmDetector {
        fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm> {
            let KeyData::Asymmetric(data) = &key.data else {
                return vec![];
            };

            match data.private_key.as_str() {
                "rsa" => vec![
                    JwaSigningAlgorithm::Rs256,
                    JwaSigningAlgorithm::Rs384,
                    JwaSigningAlgorithm::Rs512,
                ],
                "ps256" => vec![JwaSigningAlgorithm::Ps256],
                "ps384" => vec![JwaSigningAlgorithm::Ps384],
                "ps512" => vec![JwaSigningAlgorithm::Ps512],
                "ec-p256" => vec![JwaSigningAlgorithm::Es256],
                "ec-p384" => vec![JwaSigningAlgorithm::Es384],
                "ec-p521" => vec![JwaSigningAlgorithm::Es512],
                "ec-secp256k1" => vec![JwaSigningAlgorithm::Es256k],
                "ed25519" => vec![JwaSigningAlgorithm::EdDsa],
                _ => vec![],
            }
        }
    }

    fn test_signing_algorithm_detector() -> Arc<dyn SigningAlgorithmDetector> {
        Arc::new(TestSigningAlgorithmDetector)
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
        "rsa".to_owned()
    }

    fn generate_rsa_pss_pem(alg: &str) -> String {
        match alg {
            "PS256" => "ps256".to_owned(),
            "PS384" => "ps384".to_owned(),
            "PS512" => "ps512".to_owned(),
            other => panic!("unsupported RSA-PSS test alg: {other}"),
        }
    }

    fn generate_ec_p256_pem() -> String {
        "ec-p256".to_owned()
    }

    fn generate_ec_p384_pem() -> String {
        "ec-p384".to_owned()
    }

    fn generate_ec_p521_pem() -> String {
        "ec-p521".to_owned()
    }

    fn generate_ec_secp256k1_pem() -> String {
        "ec-secp256k1".to_owned()
    }

    fn generate_ed25519_pem() -> String {
        "ed25519".to_owned()
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
        assert_eq!(
            metadata.end_session_endpoint.unwrap().as_str(),
            "https://identity.example.com/issuer1/oauth2/logout"
        );
        assert_eq!(
            metadata.check_session_iframe.unwrap().as_str(),
            "https://identity.example.com/issuer1/oauth2/check_session"
        );
        assert_eq!(metadata.frontchannel_logout_supported, Some(true));
        assert_eq!(metadata.frontchannel_logout_session_supported, Some(true));
        assert_eq!(metadata.backchannel_logout_supported, Some(true));
        assert_eq!(metadata.backchannel_logout_session_supported, Some(true));
        assert_eq!(
            metadata.response_types_supported,
            vec![
                "code",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token"
            ]
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
    async fn default_discovery_advertises_form_post_and_pairwise() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await;

        let metadata = service.discovery_metadata().await.unwrap();

        assert!(
            metadata
                .response_modes_supported
                .unwrap()
                .contains(&"form_post".to_owned())
        );
        assert!(
            metadata
                .subject_types_supported
                .contains(&"pairwise".to_owned())
        );
    }

    #[tokio::test]
    async fn default_discovery_advertises_request_object_verifier_algorithms() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await;

        let metadata = service.discovery_metadata().await.unwrap();
        let mut expected = vec!["none".to_owned()];
        expected.extend(
            JwaSigningAlgorithm::all()
                .iter()
                .map(|algorithm| algorithm.as_str().to_owned()),
        );

        assert_eq!(
            metadata.request_object_signing_alg_values_supported,
            Some(expected)
        );
    }

    #[tokio::test]
    async fn default_discovery_advertises_token_endpoint_auth_verifier_algorithms() {
        let service = OpenIdProviderService::for_test(InstallationState {
            initialized: true,
            domain: Some("https://identity.example.com".to_owned()),
            first_user_oid: None,
            first_key_oid: None,
            initialized_at: None,
        })
        .await;

        let metadata = service.discovery_metadata().await.unwrap();
        let mut expected = vec!["HS256".to_owned(), "HS384".to_owned(), "HS512".to_owned()];
        expected.extend(
            JwaSigningAlgorithm::all()
                .iter()
                .map(|algorithm| algorithm.as_str().to_owned()),
        );

        assert_eq!(
            metadata.token_endpoint_auth_signing_alg_values_supported,
            Some(expected)
        );
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
        )]))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

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
        ]))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

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
        )]))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

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
        ]))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

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
        use super::{
            TestSigningAlgorithmDetector, generate_ec_p256_pem, generate_ec_p384_pem,
            generate_ec_p521_pem, generate_ec_secp256k1_pem, generate_ed25519_pem,
            generate_rsa_pem, generate_rsa_pss_pem,
        };
        use crate::openid_connect::provider::detect_id_token_signing_algorithms;
        use chrono::Utc;
        use identity_domain::key::{
            Key, KeyData, KeyOid, KeyType,
            material::{AsymmetricKeyData, SymmetricKeyAlgorithm, SymmetricKeyData},
        };
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

        #[test]
        fn empty_keys_returns_empty_vec() {
            let algos = detect_id_token_signing_algorithms(&[], &TestSigningAlgorithmDetector);
            assert!(algos.is_empty());
        }

        #[test]
        fn symmetric_key_is_ignored() {
            let key = make_symmetric_key();
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(algos.is_empty());
        }

        #[test]
        fn rsa_key_detects_all_rs_variants() {
            let pem = generate_rsa_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
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
            let algos = detect_id_token_signing_algorithms(&keys, &TestSigningAlgorithmDetector);
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
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(!algos.contains(&"ES256".to_owned()));
            assert!(!algos.contains(&"ES256K".to_owned()));
            assert!(!algos.contains(&"EdDSA".to_owned()));
        }

        #[test]
        fn ec_p256_key_detects_es256() {
            let pem = generate_ec_p256_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(
                algos.contains(&"ES256".to_owned()),
                "expected ES256, got: {algos:?}"
            );
        }

        #[test]
        fn ec_p384_key_detects_es384() {
            let key = make_asymmetric_key(generate_ec_p384_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["ES384".to_owned()]);
        }

        #[test]
        fn ec_p521_key_detects_es512() {
            let key = make_asymmetric_key(generate_ec_p521_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["ES512".to_owned()]);
        }

        #[test]
        fn ec_secp256k1_key_detects_es256k() {
            let key = make_asymmetric_key(generate_ec_secp256k1_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["ES256K".to_owned()]);
        }

        #[test]
        fn ed25519_key_detects_eddsa() {
            let key = make_asymmetric_key(generate_ed25519_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["EdDSA".to_owned()]);
        }

        #[test]
        fn ec_p256_key_does_not_falsely_detect_rs_or_ed_algorithms() {
            let pem = generate_ec_p256_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(!algos.contains(&"RS256".to_owned()));
            assert!(!algos.contains(&"RS384".to_owned()));
            assert!(!algos.contains(&"EdDSA".to_owned()));
        }

        #[test]
        fn mixed_keys_detect_both_families() {
            let rsa_key = make_asymmetric_key(generate_rsa_pem());
            let ps_key = make_asymmetric_key(generate_rsa_pss_pem("PS256"));
            let ec_key = make_asymmetric_key(generate_ec_p256_pem());
            let algos = detect_id_token_signing_algorithms(
                &[rsa_key, ps_key, ec_key],
                &TestSigningAlgorithmDetector,
            );
            assert!(algos.contains(&"RS256".to_owned()));
            assert!(algos.contains(&"RS384".to_owned()));
            assert!(algos.contains(&"RS512".to_owned()));
            assert!(algos.contains(&"PS256".to_owned()));
            assert!(algos.contains(&"ES256".to_owned()));
        }
    }
}
