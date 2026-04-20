use std::sync::Arc;

use url::Url;

use crate::{
    application::{
        error::{AppError, codes::provider::ProviderErrorCode},
        setting::runtime::SettingProvider,
    },
    domain::{
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
            ],
            response_types_supported: vec![
                "code".to_owned(),
                "id_token".to_owned(),
                "token id_token".to_owned(),
            ],
            response_modes_supported: vec!["query".to_owned(), "fragment".to_owned()],
            grant_types_supported: vec!["authorization_code".to_owned(), "implicit".to_owned()],
            acr_values_supported: vec![],
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
                "private_key_jwt".to_owned(),
            ],
            token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_owned()],
            display_values_supported: vec!["page".to_owned()],
            claim_types_supported: vec!["normal".to_owned()],
            claims_supported: vec![
                JwtClaimNames::SUB.to_owned(),
                JwtClaimNames::ISS.to_owned(),
                JwtClaimNames::AUTH_TIME.to_owned(),
                JwtClaimNames::NAME.to_owned(),
                JwtClaimNames::EMAIL.to_owned(),
                JwtClaimNames::EMAIL_VERIFIED.to_owned(),
            ],
            claims_locales_supported: vec![],
            ui_locales_supported: vec![],
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: true,
            require_request_uri_registration: false,
        }
    }
}

#[derive(Clone)]
pub struct OpenIdProviderService {
    installation_setting: Arc<dyn SettingProvider<InstallationSetting>>,
    capabilities: OpenIdProviderCapabilities,
}

impl OpenIdProviderService {
    pub fn new(installation_setting: Arc<dyn SettingProvider<InstallationSetting>>) -> Self {
        Self {
            installation_setting,
            capabilities: OpenIdProviderCapabilities::default(),
        }
    }

    pub fn with_capabilities(
        installation_setting: Arc<dyn SettingProvider<InstallationSetting>>,
        capabilities: OpenIdProviderCapabilities,
    ) -> Self {
        Self {
            installation_setting,
            capabilities,
        }
    }

    pub fn issuer(&self) -> Result<Url, AppError> {
        let installation = self.installation_setting.current_value();
        canonical_issuer(installation.as_ref())
    }

    pub fn discovery_metadata(&self) -> Result<OpenIdProviderMetadata, AppError> {
        let issuer = self.issuer()?;

        Ok(OpenIdProviderMetadata {
            issuer: issuer.clone(),
            authorization_endpoint: endpoint_url(&issuer, "/oauth2/authorize")?,
            token_endpoint: Some(endpoint_url(&issuer, "/oauth2/token")?),
            userinfo_endpoint: Some(endpoint_url(&issuer, "/oauth2/userinfo")?),
            jwks_uri: endpoint_url(&issuer, "/.well-known/keys")?,
            registration_endpoint: Some(endpoint_url(&issuer, "/oauth2/register")?),
            scopes_supported: non_empty(self.capabilities.scopes_supported.clone()),
            response_types_supported: self.capabilities.response_types_supported.clone(),
            response_modes_supported: non_empty(self.capabilities.response_modes_supported.clone()),
            grant_types_supported: non_empty(self.capabilities.grant_types_supported.clone()),
            acr_values_supported: non_empty(self.capabilities.acr_values_supported.clone()),
            subject_types_supported: self.capabilities.subject_types_supported.clone(),
            id_token_signing_alg_values_supported: self
                .capabilities
                .id_token_signing_alg_values_supported
                .clone(),
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
            end_session_endpoint: Some(endpoint_url(&issuer, "/openid/endsession")?),
        })
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
    use serde_json::to_value;
    use uuid::Uuid;

    use super::OpenIdProviderService;
    use crate::{
        application::setting::runtime::CachedSetting,
        domain::setting::{
            installation::{InstallationSetting, InstallationState},
            model::{SettingDefinition, SettingEntry},
            repository::{SettingRepository, SettingRepositoryError},
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

        let metadata = service.discovery_metadata().unwrap();

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
            "https://identity.example.com/issuer1/openid/endsession"
        );
        assert_eq!(
            metadata.response_types_supported,
            vec!["code", "id_token", "token id_token"]
        );
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
}
