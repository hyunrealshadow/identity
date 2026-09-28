use std::sync::Arc;

use url::Url;

use crate::{
    application::{
        error::{AppError, codes::provider::ProviderErrorCode},
        setting::{AppSettings, InstallationSettings, OpenIdConnectSettings, SettingsSource},
    },
    domain::{
        key::{
            JwaEncryptionAlgorithm, JwaSigningAlgorithm, JweContentEncryption, JwkAlgorithm,
            JwsAlgorithm, Key, KeyData, KeyJwkRepository, repository::KeyRepository,
        },
        openid_connect::{
            ApiScope, ClaimType, Display, GrantType, OpenIdProviderMetadata, ResponseMode,
            ResponseType, SubjectType, TokenEndpointAuthMethod,
            model::claim::{JwtClaimNames, StandardScopes},
        },
    },
};

#[derive(Debug, Clone)]
pub struct OpenIdProviderCapabilities {
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<ResponseType>,
    pub response_modes_supported: Vec<ResponseMode>,
    pub grant_types_supported: Vec<GrantType>,
    pub acr_values_supported: Vec<String>,
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub id_token_encryption_alg_values_supported: Vec<JwaEncryptionAlgorithm>,
    pub id_token_encryption_enc_values_supported: Vec<JweContentEncryption>,
    pub userinfo_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub userinfo_encryption_alg_values_supported: Vec<JwaEncryptionAlgorithm>,
    pub userinfo_encryption_enc_values_supported: Vec<JweContentEncryption>,
    pub request_object_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub request_object_encryption_alg_values_supported: Vec<JwaEncryptionAlgorithm>,
    pub request_object_encryption_enc_values_supported: Vec<JweContentEncryption>,
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub display_values_supported: Vec<Display>,
    pub claim_types_supported: Vec<ClaimType>,
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
                ApiScope::ACCOUNT.to_owned(),
                ApiScope::ACCOUNT_UPDATE.to_owned(),
                ApiScope::ACCOUNT_READ.to_owned(),
                ApiScope::SESSION.to_owned(),
                ApiScope::SESSION_REVOKE.to_owned(),
                ApiScope::SESSION_READ.to_owned(),
                ApiScope::PASSWORD_CHANGE.to_owned(),
            ],
            response_types_supported: vec![
                ResponseType::Code,
                ResponseType::IdToken,
                ResponseType::TokenIdToken,
                ResponseType::CodeIdToken,
                ResponseType::CodeToken,
                ResponseType::CodeTokenIdToken,
            ],
            response_modes_supported: vec![
                ResponseMode::Query,
                ResponseMode::Fragment,
                ResponseMode::FormPost,
            ],
            grant_types_supported: vec![
                GrantType::AuthorizationCode,
                GrantType::Implicit,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
                GrantType::DeviceCode,
            ],
            acr_values_supported: vec![
                identity_domain::auth::ACR_AAL1.to_owned(),
                identity_domain::auth::ACR_AAL2.to_owned(),
            ],
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            id_token_signing_alg_values_supported: vec![JwsAlgorithm::Asymmetric(
                JwaSigningAlgorithm::Es256,
            )],
            id_token_encryption_alg_values_supported: vec![
                JwaEncryptionAlgorithm::RsaOaep,
                JwaEncryptionAlgorithm::RsaOaep256,
                JwaEncryptionAlgorithm::EcdhEs,
                JwaEncryptionAlgorithm::EcdhEsA128Kw,
                JwaEncryptionAlgorithm::EcdhEsA256Kw,
            ],
            id_token_encryption_enc_values_supported: vec![
                JweContentEncryption::A128CbcHs256,
                JweContentEncryption::A256CbcHs512,
                JweContentEncryption::A128Gcm,
                JweContentEncryption::A256Gcm,
            ],
            userinfo_signing_alg_values_supported: vec![],
            userinfo_encryption_alg_values_supported: vec![
                JwaEncryptionAlgorithm::RsaOaep,
                JwaEncryptionAlgorithm::RsaOaep256,
                JwaEncryptionAlgorithm::EcdhEs,
                JwaEncryptionAlgorithm::EcdhEsA128Kw,
                JwaEncryptionAlgorithm::EcdhEsA256Kw,
            ],
            userinfo_encryption_enc_values_supported: vec![
                JweContentEncryption::A128CbcHs256,
                JweContentEncryption::A256CbcHs512,
                JweContentEncryption::A128Gcm,
                JweContentEncryption::A256Gcm,
            ],
            request_object_signing_alg_values_supported:
                supported_request_object_signing_algorithms(),
            request_object_encryption_alg_values_supported:
                super::jose::request_object_encryption_algorithms()
                    .into_iter()
                    .map(|value| value.parse().expect("supported JWE algorithm"))
                    .collect(),
            request_object_encryption_enc_values_supported:
                super::jose::request_object_content_encryption_algorithms()
                    .into_iter()
                    .map(|value| value.parse().expect("supported JWE content encryption"))
                    .collect(),
            token_endpoint_auth_methods_supported: supported_token_endpoint_auth_methods(),
            token_endpoint_auth_signing_alg_values_supported:
                supported_token_endpoint_auth_signing_algorithms(),
            display_values_supported: vec![Display::Page],
            claim_types_supported: vec![ClaimType::Normal],
            claims_supported: vec![
                JwtClaimNames::SUB.to_owned(),
                JwtClaimNames::ISS.to_owned(),
                JwtClaimNames::AUTH_TIME.to_owned(),
                JwtClaimNames::ACR.to_owned(),
                JwtClaimNames::AMR.to_owned(),
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

fn supported_request_object_signing_algorithms() -> Vec<JwsAlgorithm> {
    let mut algorithms = vec![JwsAlgorithm::None];
    algorithms.extend(supported_asymmetric_jws_algorithms());
    algorithms
}

fn supported_token_endpoint_auth_signing_algorithms() -> Vec<JwsAlgorithm> {
    let mut algorithms = vec![
        JwsAlgorithm::Hs256,
        JwsAlgorithm::Hs384,
        JwsAlgorithm::Hs512,
    ];
    algorithms.extend(supported_asymmetric_jws_algorithms());
    algorithms
}

fn supported_token_endpoint_auth_methods() -> Vec<TokenEndpointAuthMethod> {
    vec![
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretPost,
        TokenEndpointAuthMethod::ClientSecretJwt,
        TokenEndpointAuthMethod::PrivateKeyJwt,
        TokenEndpointAuthMethod::None,
    ]
}

fn supported_asymmetric_jws_algorithms() -> Vec<JwsAlgorithm> {
    JwaSigningAlgorithm::all()
        .iter()
        .copied()
        .map(JwsAlgorithm::Asymmetric)
        .collect()
}

#[derive(Clone)]
pub struct OpenIdProviderService {
    settings: Arc<dyn SettingsSource>,
    capabilities: OpenIdProviderCapabilities,
    key_repo: Option<Arc<dyn KeyRepository>>,
    key_jwk_repo: Option<Arc<dyn KeyJwkRepository>>,
    signing_algorithm_detector: Option<Arc<dyn SigningAlgorithmDetector>>,
}

fn detect_id_token_signing_algorithms(
    keys: &[Key],
    detector: &dyn SigningAlgorithmDetector,
) -> Vec<JwsAlgorithm> {
    let mut algos = Vec::new();
    for key in keys {
        if let KeyData::Asymmetric(_) = key.data {
            algos.extend(
                detector
                    .detect(key)
                    .into_iter()
                    .map(JwsAlgorithm::Asymmetric),
            );
        }
    }
    algos.sort_unstable_by_key(|algorithm| algorithm.as_str());
    algos.dedup();
    algos
}

impl OpenIdProviderService {
    pub fn new(settings: Arc<dyn SettingsSource>) -> Self {
        Self {
            settings,
            capabilities: OpenIdProviderCapabilities::default(),
            key_repo: None,
            key_jwk_repo: None,
            signing_algorithm_detector: None,
        }
    }

    pub fn with_capabilities(
        settings: Arc<dyn SettingsSource>,
        capabilities: OpenIdProviderCapabilities,
    ) -> Self {
        Self {
            settings,
            capabilities,
            key_repo: None,
            key_jwk_repo: None,
            signing_algorithm_detector: None,
        }
    }

    pub fn with_key_repo(mut self, key_repo: Arc<dyn KeyRepository>) -> Self {
        self.key_repo = Some(key_repo);
        self
    }

    pub fn with_key_jwk_repo(mut self, key_jwk_repo: Arc<dyn KeyJwkRepository>) -> Self {
        self.key_jwk_repo = Some(key_jwk_repo);
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
        let snapshot = self.settings.snapshot();
        normalize_issuer(
            &snapshot.section::<InstallationSettings>(),
            snapshot.section::<AppSettings>().domain.as_deref(),
        )
    }

    pub async fn discovery_metadata(&self) -> Result<OpenIdProviderMetadata, AppError> {
        let issuer = self.issuer()?;

        let id_token_algos = self.compute_id_token_signing_algos().await?;

        Ok(OpenIdProviderMetadata {
            issuer: issuer.clone(),
            authorization_endpoint: endpoint_url(&issuer, "/oauth2/authorize")?,
            token_endpoint: Some(endpoint_url(&issuer, "/oauth2/token")?),
            revocation_endpoint: endpoint_url(&issuer, "/oauth2/revoke")?,
            userinfo_endpoint: Some(endpoint_url(&issuer, "/oauth2/userinfo")?),
            device_authorization_endpoint: Some(endpoint_url(&issuer, "/oauth2/device")?),
            jwks_uri: endpoint_url(&issuer, "/.well-known/keys")?,
            registration_endpoint: self.registration_endpoint(&issuer)?,
            scopes_supported: non_empty(self.capabilities.scopes_supported.clone()),
            response_types_supported: to_string_values(&self.capabilities.response_types_supported),
            response_modes_supported: non_empty(to_string_values(
                &self.capabilities.response_modes_supported,
            )),
            grant_types_supported: non_empty(to_string_values(
                &self.capabilities.grant_types_supported,
            )),
            code_challenge_methods_supported: vec!["S256".to_owned()],
            acr_values_supported: non_empty(self.capabilities.acr_values_supported.clone()),
            subject_types_supported: to_string_values(&self.capabilities.subject_types_supported),
            id_token_signing_alg_values_supported: to_string_values(&id_token_algos),
            id_token_encryption_alg_values_supported: non_empty(to_string_values(
                &self.capabilities.id_token_encryption_alg_values_supported,
            )),
            id_token_encryption_enc_values_supported: non_empty(to_string_values(
                &self.capabilities.id_token_encryption_enc_values_supported,
            )),
            userinfo_signing_alg_values_supported: non_empty(to_string_values(&id_token_algos)),
            userinfo_encryption_alg_values_supported: non_empty(to_string_values(
                &self.capabilities.userinfo_encryption_alg_values_supported,
            )),
            userinfo_encryption_enc_values_supported: non_empty(to_string_values(
                &self.capabilities.userinfo_encryption_enc_values_supported,
            )),
            request_object_signing_alg_values_supported: non_empty(to_string_values(
                &self
                    .capabilities
                    .request_object_signing_alg_values_supported,
            )),
            request_object_encryption_alg_values_supported: non_empty(to_string_values(
                &self
                    .capabilities
                    .request_object_encryption_alg_values_supported,
            )),
            request_object_encryption_enc_values_supported: non_empty(to_string_values(
                &self
                    .capabilities
                    .request_object_encryption_enc_values_supported,
            )),
            token_endpoint_auth_methods_supported: non_empty(to_string_values(
                &self.capabilities.token_endpoint_auth_methods_supported,
            )),
            token_endpoint_auth_signing_alg_values_supported: non_empty(to_string_values(
                &self
                    .capabilities
                    .token_endpoint_auth_signing_alg_values_supported,
            )),
            display_values_supported: non_empty(to_string_values(
                &self.capabilities.display_values_supported,
            )),
            claim_types_supported: non_empty(to_string_values(
                &self.capabilities.claim_types_supported,
            )),
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

    async fn compute_id_token_signing_algos(&self) -> Result<Vec<JwsAlgorithm>, AppError> {
        let values = match self.key_repo {
            Some(ref key_repo) => {
                let keys = key_repo.list_active_asymmetric().await.map_err(|error| {
                    AppError::from_code(ProviderErrorCode::KeyLookupFailed).with_source(error)
                })?;
                if let Some(key_jwk_repo) = &self.key_jwk_repo {
                    let bindings = key_jwk_repo.list_active().await.map_err(|error| {
                        AppError::from_code(ProviderErrorCode::KeyLookupFailed).with_source(error)
                    })?;
                    let mut algorithms = bindings
                        .into_iter()
                        .filter(|binding| keys.iter().any(|key| key.oid == binding.key_oid))
                        .filter_map(|binding| match binding.algorithm {
                            JwkAlgorithm::Signing(algorithm) => {
                                Some(JwsAlgorithm::Asymmetric(algorithm))
                            }
                            JwkAlgorithm::Encryption(_) => None,
                        })
                        .collect::<Vec<_>>();
                    algorithms.sort_unstable_by_key(|algorithm| algorithm.as_str());
                    algorithms.dedup();
                    return Ok(append_conformance_none_alg(algorithms));
                }
                let detected = self
                    .signing_algorithm_detector
                    .as_ref()
                    .map(|detector| detect_id_token_signing_algorithms(&keys, detector.as_ref()))
                    .unwrap_or_default();
                if detected.is_empty() {
                    self.capabilities
                        .id_token_signing_alg_values_supported
                        .clone()
                } else {
                    detected
                }
            }
            None => self
                .capabilities
                .id_token_signing_alg_values_supported
                .clone(),
        };
        Ok(append_conformance_none_alg(values))
    }

    fn registration_endpoint(&self, issuer: &Url) -> Result<Option<Url>, AppError> {
        if self
            .settings
            .snapshot()
            .section::<OpenIdConnectSettings>()
            .dynamic_registration
            .enabled
        {
            endpoint_url(issuer, "/oauth2/register").map(Some)
        } else {
            Ok(None)
        }
    }
}

#[cfg(feature = "allow-none-alg")]
fn append_conformance_none_alg(mut values: Vec<JwsAlgorithm>) -> Vec<JwsAlgorithm> {
    if !values.contains(&JwsAlgorithm::None) {
        values.push(JwsAlgorithm::None);
    }
    values
}

#[cfg(not(feature = "allow-none-alg"))]
fn append_conformance_none_alg(values: Vec<JwsAlgorithm>) -> Vec<JwsAlgorithm> {
    values
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

fn normalize_issuer(
    installation: &InstallationSettings,
    domain: Option<&str>,
) -> Result<Url, AppError> {
    if !installation.initialized {
        return Err(AppError::from_code(ProviderErrorCode::NotInitialized));
    }

    let raw = domain
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
    use crate::setting::{AppSettings, InstallationSettings, SettingsSnapshot};
    use std::sync::Arc;

    use chrono::Utc;
    use uuid::Uuid;

    use super::{OpenIdProviderService, SigningAlgorithmDetector};
    use crate::{
        domain::key::{
            JwaSigningAlgorithm, JwkAlgorithm, Key, KeyData, KeyJwk, KeyJwkOid, KeyOid, KeyType,
            PublicJwk, material::AsymmetricKeyData, repository::KeyRepositoryError,
        },
        openid_connect::tests::fixtures::mocks::{MockKeyJwkRepository, MockKeyRepository},
        setting::{DynamicRegistrationSettings, OpenIdConnectSettings},
    };

    fn static_settings(
        settings: SettingsSnapshot,
        dynamic_client_registration: bool,
    ) -> Arc<SettingsSnapshot> {
        Arc::new(settings.with_section(&OpenIdConnectSettings {
            dynamic_registration: DynamicRegistrationSettings {
                enabled: dynamic_client_registration,
            },
            ..OpenIdConnectSettings::default()
        }))
    }

    #[cfg(feature = "allow-none-alg")]
    fn expected_id_token_algorithms(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .copied()
            .chain(std::iter::once("none"))
            .map(str::to_owned)
            .collect()
    }

    #[cfg(not(feature = "allow-none-alg"))]
    fn expected_id_token_algorithms(values: &[&str]) -> Vec<String> {
        values.iter().copied().map(str::to_owned).collect()
    }

    fn key_repo_with_keys(keys: Vec<Key>) -> MockKeyRepository {
        let mut mock = MockKeyRepository::new();
        let k = keys.clone();
        mock.expect_find_by_oid()
            .returning(move |oid| Ok(k.iter().find(|key| key.oid == oid).cloned()));
        let k = keys;
        mock.expect_list_active_asymmetric()
            .returning(move || Ok(k.clone()));
        mock.expect_list_decryptable_symmetric()
            .returning(|| Ok(vec![]));
        mock
    }

    fn key_repo_failing() -> MockKeyRepository {
        let mut mock = MockKeyRepository::new();
        mock.expect_find_by_oid().returning(|_| Ok(None));
        mock.expect_list_active_asymmetric().returning(|| {
            Err(KeyRepositoryError::ListAvailableFailed(Box::new(
                sea_orm::DbErr::Custom("boom".to_owned()),
            )))
        });
        mock.expect_list_decryptable_symmetric()
            .returning(|| Ok(vec![]));
        mock
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
    async fn normalizes_plain_domain_to_https_issuer() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await;

        let issuer = service.issuer().unwrap();

        assert_eq!(issuer.as_str(), "https://identity.example.com/");
    }

    #[tokio::test]
    async fn assembles_discovery_document_from_issuer_and_capabilities() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com/issuer1/".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
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
    async fn default_discovery_advertises_the_device_authorization_endpoint() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await;

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata
                .device_authorization_endpoint
                .expect("device authorization endpoint is advertised")
                .as_str(),
            "https://identity.example.com/oauth2/device"
        );
        assert!(
            metadata
                .grant_types_supported
                .expect("grant types are advertised")
                .iter()
                .any(|grant| grant == "urn:ietf:params:oauth:grant-type:device_code"),
            "discovery must advertise the device_code grant it accepts"
        );
    }

    #[tokio::test]
    async fn default_discovery_advertises_supported_address_and_phone_claims() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await;

        let metadata = service.discovery_metadata().await.unwrap();
        let scopes = metadata.scopes_supported.unwrap();
        let claims = metadata.claims_supported.unwrap();

        assert!(scopes.iter().any(|scope| scope == "address"));
        assert!(scopes.iter().any(|scope| scope == "phone"));
        assert!(claims.iter().any(|claim| claim == "address"));
        assert!(claims.iter().any(|claim| claim == "phone_number"));
        assert!(claims.iter().any(|claim| claim == "phone_number_verified"));
        assert!(claims.iter().any(|claim| claim == "amr"));
    }

    #[tokio::test]
    async fn default_discovery_advertises_form_post_and_pairwise() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
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
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
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
    async fn default_discovery_advertises_request_object_encryption() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await;

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.request_object_encryption_alg_values_supported,
            Some(super::super::jose::request_object_encryption_algorithms())
        );
        assert_eq!(
            metadata.request_object_encryption_enc_values_supported,
            Some(super::super::jose::request_object_content_encryption_algorithms())
        );
    }

    #[tokio::test]
    async fn discovery_advertises_registration_endpoint_when_enabled() {
        let service = OpenIdProviderService::for_test_with_registration(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await;

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.registration_endpoint.unwrap().as_str(),
            "https://identity.example.com/oauth2/register"
        );
    }

    #[tokio::test]
    async fn discovery_advertises_public_client_auth_method() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await;

        let metadata = service.discovery_metadata().await.unwrap();
        let methods = metadata.token_endpoint_auth_methods_supported.unwrap();

        assert!(methods.iter().any(|method| method == "none"));
    }

    #[tokio::test]
    async fn default_discovery_advertises_token_endpoint_auth_verifier_algorithms() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
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
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_with_keys(vec![make_asymmetric_key(
            generate_rsa_pem(),
        )])))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            expected_id_token_algorithms(&["RS256", "RS384", "RS512"])
        );
    }

    #[tokio::test]
    async fn discovery_advertises_only_published_signing_algorithms() {
        let key = make_asymmetric_key(generate_rsa_pem());
        let binding = KeyJwk {
            oid: KeyJwkOid(Uuid::new_v4()),
            key_oid: key.oid,
            algorithm: JwkAlgorithm::Signing(JwaSigningAlgorithm::Rs256),
            jwk: PublicJwk::Rsa {
                key_use: Some("sig".to_owned()),
                alg: Some("RS256".to_owned()),
                kid: Some(Uuid::new_v4().to_string()),
                n: "AQAB".to_owned(),
                e: "AQAB".to_owned(),
                x5c: None,
                x5t: None,
                x5t_s256: None,
            },
            created_at: Utc::now(),
        };
        let mut jwk_repo = MockKeyJwkRepository::new();
        jwk_repo
            .expect_list_active()
            .returning(move || Ok(vec![binding.clone()]));
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_with_keys(vec![key])))
        .with_key_jwk_repo(Arc::new(jwk_repo));

        let metadata = service.discovery_metadata().await.unwrap();
        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            expected_id_token_algorithms(&["RS256"]),
        );
    }

    #[tokio::test]
    async fn discovery_uses_rsa_pss_key_repo_algorithm() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_with_keys(vec![
            make_asymmetric_key(generate_rsa_pss_pem("PS256")),
            make_asymmetric_key(generate_rsa_pss_pem("PS384")),
            make_asymmetric_key(generate_rsa_pss_pem("PS512")),
        ])))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            expected_id_token_algorithms(&["PS256", "PS384", "PS512"])
        );
    }

    #[tokio::test]
    async fn discovery_uses_ec_key_repo_algorithm() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_with_keys(vec![make_asymmetric_key(
            generate_ec_p256_pem(),
        )])))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            expected_id_token_algorithms(&["ES256"])
        );
    }

    #[tokio::test]
    async fn discovery_uses_all_detected_key_repo_algorithms() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_with_keys(vec![
            make_asymmetric_key(generate_rsa_pem()),
            make_asymmetric_key(generate_rsa_pss_pem("PS256")),
            make_asymmetric_key(generate_rsa_pss_pem("PS384")),
            make_asymmetric_key(generate_rsa_pss_pem("PS512")),
            make_asymmetric_key(generate_ec_p256_pem()),
            make_asymmetric_key(generate_ec_p384_pem()),
            make_asymmetric_key(generate_ec_p521_pem()),
            make_asymmetric_key(generate_ec_secp256k1_pem()),
            make_asymmetric_key(generate_ed25519_pem()),
        ])))
        .with_signing_algorithm_detector(test_signing_algorithm_detector());

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            expected_id_token_algorithms(&[
                "ES256", "ES256K", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256",
                "RS384", "RS512",
            ])
        );
    }

    #[tokio::test]
    async fn discovery_falls_back_to_capabilities_when_key_repo_has_no_detected_algorithms() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_with_keys(vec![])));

        let metadata = service.discovery_metadata().await.unwrap();

        assert_eq!(
            metadata.id_token_signing_alg_values_supported,
            expected_id_token_algorithms(&["ES256"])
        );
    }

    #[tokio::test]
    async fn discovery_maps_key_repo_errors() {
        let service = OpenIdProviderService::for_test(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("https://identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        )
        .await
        .with_key_repo(Arc::new(key_repo_failing()));

        let error = service.discovery_metadata().await.unwrap_err();

        assert_eq!(error.code(), 20005);
    }

    impl OpenIdProviderService {
        async fn for_test(state: SettingsSnapshot) -> Self {
            Self::new(static_settings(state, false))
        }

        async fn for_test_with_registration(state: SettingsSnapshot) -> Self {
            Self::new(static_settings(state, true))
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
                algos.contains(&"RS256".parse().unwrap()),
                "expected RS256, got: {algos:?}"
            );
            assert!(
                algos.contains(&"RS384".parse().unwrap()),
                "expected RS384, got: {algos:?}"
            );
            assert!(
                algos.contains(&"RS512".parse().unwrap()),
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
                algos.contains(&"PS256".parse().unwrap()),
                "expected PS256, got: {algos:?}"
            );
            assert!(
                algos.contains(&"PS384".parse().unwrap()),
                "expected PS384, got: {algos:?}"
            );
            assert!(
                algos.contains(&"PS512".parse().unwrap()),
                "expected PS512, got: {algos:?}"
            );
        }

        #[test]
        fn rsa_key_does_not_falsely_detect_ec_algorithms() {
            let pem = generate_rsa_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(!algos.contains(&"ES256".parse().unwrap()));
            assert!(!algos.contains(&"ES256K".parse().unwrap()));
            assert!(!algos.contains(&"EdDSA".parse().unwrap()));
        }

        #[test]
        fn ec_p256_key_detects_es256() {
            let pem = generate_ec_p256_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(
                algos.contains(&"ES256".parse().unwrap()),
                "expected ES256, got: {algos:?}"
            );
        }

        #[test]
        fn ec_p384_key_detects_es384() {
            let key = make_asymmetric_key(generate_ec_p384_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["ES384".parse().unwrap()]);
        }

        #[test]
        fn ec_p521_key_detects_es512() {
            let key = make_asymmetric_key(generate_ec_p521_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["ES512".parse().unwrap()]);
        }

        #[test]
        fn ec_secp256k1_key_detects_es256k() {
            let key = make_asymmetric_key(generate_ec_secp256k1_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["ES256K".parse().unwrap()]);
        }

        #[test]
        fn ed25519_key_detects_eddsa() {
            let key = make_asymmetric_key(generate_ed25519_pem());
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert_eq!(algos, vec!["EdDSA".parse().unwrap()]);
        }

        #[test]
        fn ec_p256_key_does_not_falsely_detect_rs_or_ed_algorithms() {
            let pem = generate_ec_p256_pem();
            let key = make_asymmetric_key(pem);
            let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
            assert!(!algos.contains(&"RS256".parse().unwrap()));
            assert!(!algos.contains(&"RS384".parse().unwrap()));
            assert!(!algos.contains(&"EdDSA".parse().unwrap()));
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
            assert!(algos.contains(&"RS256".parse().unwrap()));
            assert!(algos.contains(&"RS384".parse().unwrap()));
            assert!(algos.contains(&"RS512".parse().unwrap()));
            assert!(algos.contains(&"PS256".parse().unwrap()));
            assert!(algos.contains(&"ES256".parse().unwrap()));
        }
    }
}
