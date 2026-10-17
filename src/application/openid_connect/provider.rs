//! Provider composition, scope policies, and public discovery interface.

use crate::{
    error::{AppError, codes::common::CommonErrorCode},
    setting::{OpenIdConnectSettings, PushedAuthorizationSettings, SettingsSource},
};
use identity_domain::{
    key::{KeyJwkRepository, repository::KeyRepository},
    openid_connect::{
        OAuthProtocolVersion, OpenIdConnectClient, ScopeSet, resource::OAuthResourceRepository,
        scope_catalog::ScopeCatalogRepository,
    },
};
use std::sync::Arc;

mod capabilities;
mod discovery;
mod signing;
pub use capabilities::OpenIdProviderCapabilities;
pub use signing::SigningAlgorithmDetector;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct OpenIdProviderService {
    settings: Arc<dyn SettingsSource>,
    pub(super) capabilities: OpenIdProviderCapabilities,
    pub(super) resource_repo: Option<Arc<dyn OAuthResourceRepository>>,
    scope_catalog: Option<Arc<dyn ScopeCatalogRepository>>,
    key_repo: Option<Arc<dyn KeyRepository>>,
    key_jwk_repo: Option<Arc<dyn KeyJwkRepository>>,
    signing_algorithm_detector: Option<Arc<dyn SigningAlgorithmDetector>>,
}

impl OpenIdProviderService {
    pub fn new(settings: Arc<dyn SettingsSource>) -> Self {
        Self {
            settings,
            capabilities: OpenIdProviderCapabilities::default(),
            resource_repo: None,
            scope_catalog: None,
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
            resource_repo: None,
            scope_catalog: None,
            key_repo: None,
            key_jwk_repo: None,
            signing_algorithm_detector: None,
        }
    }

    pub fn with_resource_repo(mut self, repo: Arc<dyn OAuthResourceRepository>) -> Self {
        self.resource_repo = Some(repo);
        self
    }

    pub fn with_scope_catalog(mut self, repo: Arc<dyn ScopeCatalogRepository>) -> Self {
        self.scope_catalog = Some(repo);
        self
    }

    pub async fn supported_scopes(&self) -> Result<Vec<String>, AppError> {
        match &self.scope_catalog {
            Some(repo) => repo.list_names().await.map_err(AppError::internal),
            None => Ok(self.capabilities.scopes_supported.clone()),
        }
    }

    pub async fn validate_scope_names(&self, scope: &str) -> Result<(), AppError> {
        // Validate every requested name before domain normalization of built-in scopes.
        ScopeSet::parse(scope).map_err(AppError::map_source(CommonErrorCode::InvalidScope))?;
        let supported = self.supported_scopes().await?;
        if scope
            .split(' ')
            .filter(|name| !name.is_empty())
            .any(|name| !supported.iter().any(|item| item == name))
        {
            return Err(AppError::from_code(CommonErrorCode::InvalidScope));
        }
        Ok(())
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

    /// Explicit client configuration takes precedence over the live global default.
    pub fn oauth_version(&self, client: &OpenIdConnectClient) -> OAuthProtocolVersion {
        client.metadata().settings.oauth_version.unwrap_or_else(|| {
            self.settings
                .snapshot()
                .section::<OpenIdConnectSettings>()
                .oauth_version
        })
    }

    pub fn pushed_authorization_settings(&self) -> PushedAuthorizationSettings {
        self.settings
            .snapshot()
            .section::<OpenIdConnectSettings>()
            .pushed_authorization
    }
}
