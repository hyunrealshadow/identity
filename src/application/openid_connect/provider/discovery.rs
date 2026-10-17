use super::OpenIdProviderService;
use crate::{
    error::{AppError, codes::provider::ProviderErrorCode},
    setting::{AppSettings, InstallationSettings, OpenIdConnectSettings},
};
use identity_domain::openid_connect::OpenIdProviderMetadata;
use url::Url;

impl OpenIdProviderService {
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
            pushed_authorization_request_endpoint: Some(endpoint_url(&issuer, "/oauth2/par")?),
            require_pushed_authorization_requests: self
                .pushed_authorization_settings()
                .require_pushed_authorization_requests,
            revocation_endpoint: endpoint_url(&issuer, "/oauth2/revoke")?,
            introspection_endpoint: endpoint_url(&issuer, "/oauth2/introspect")?,
            introspection_endpoint_auth_methods_supported: to_string_values(
                &self.capabilities.token_endpoint_auth_methods_supported,
            )
            .into_iter()
            .filter(|method| method != "none")
            .collect(),
            introspection_endpoint_auth_signing_alg_values_supported: to_string_values(
                &self
                    .capabilities
                    .token_endpoint_auth_signing_alg_values_supported,
            ),
            revocation_endpoint_auth_methods_supported: to_string_values(
                &self.capabilities.token_endpoint_auth_methods_supported,
            ),
            revocation_endpoint_auth_signing_alg_values_supported: to_string_values(
                &self
                    .capabilities
                    .token_endpoint_auth_signing_alg_values_supported,
            ),
            userinfo_endpoint: Some(endpoint_url(&issuer, "/oauth2/userinfo")?),
            device_authorization_endpoint: Some(endpoint_url(&issuer, "/oauth2/device")?),
            jwks_uri: endpoint_url(&issuer, "/.well-known/keys")?,
            registration_endpoint: self.registration_endpoint(&issuer)?,
            scopes_supported: non_empty(self.supported_scopes().await?),
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

fn non_empty(values: Vec<String>) -> Option<Vec<String>> {
    (!values.is_empty()).then_some(values)
}

fn to_string_values<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn endpoint_url(issuer: &Url, path: &str) -> Result<Url, AppError> {
    let base = issuer.as_str().trim_end_matches('/');
    Url::parse(&format!("{base}{path}")).map_err(AppError::map_source(
        ProviderErrorCode::IssuerUrlParseFailed,
    ))
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

    let mut issuer = Url::parse(&candidate).map_err(AppError::map_source(
        ProviderErrorCode::IssuerUrlParseFailed,
    ))?;

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
