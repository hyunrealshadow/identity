//! Provider composition, scope policies, and public discovery interface.

pub(crate) use discovery::normalize_issuer;

use crate::{
    error::{AppError, codes::common::CommonErrorCode},
    setting::{OpenIdConnectSettings, PushedAuthorizationSettings, SettingsSource},
};
use identity_domain::{
    authorization::{PolicyVersion, catalog, catalog::ManagementScope},
    client::model::ClientOid,
    key::{KeyJwkRepository, repository::KeyRepository},
    openid_connect::{
        API_RESOURCE, OAuthProtocolVersion, OpenIdConnectClient, ScopeSet, is_scope_pattern,
        resource::OAuthResourceRepository, scope_catalog::ScopeCatalogRepository,
        scope_pattern_matches,
    },
    rbac::{RbacAuthorizationRepository, deterministic_oid},
};
use std::{collections::BTreeSet, sync::Arc};

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
    pub(super) rbac_authorization_repo: Option<Arc<dyn RbacAuthorizationRepository>>,
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
            rbac_authorization_repo: None,
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
            rbac_authorization_repo: None,
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

    /// Attach live business RBAC policy reads. RBAC resources fail closed when
    /// this port is absent; legacy resources keep their previous behavior.
    pub fn with_rbac_authorization_repository(
        mut self,
        repo: Arc<dyn RbacAuthorizationRepository>,
    ) -> Self {
        self.rbac_authorization_repo = Some(repo);
        self
    }

    #[must_use]
    pub fn rbac_authorization_repo(&self) -> Option<&Arc<dyn RbacAuthorizationRepository>> {
        self.rbac_authorization_repo.as_ref()
    }

    /// Whether any target is a business API resource rather than the built-in
    /// first-party GraphQL resource. All non-default resources use canonical
    /// resource-owned scopes.
    pub async fn has_rbac_resource(&self, resources: &[String]) -> Result<bool, AppError> {
        for resource in resources {
            if resource == API_RESOURCE {
                continue;
            }
            match &self.resource_repo {
                Some(repo) => {
                    let found = repo
                        .find_by_uri(resource)
                        .await
                        .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?;
                    if found.is_none() {
                        return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                    }
                    return Ok(true);
                }
                None => return Err(AppError::from_code(CommonErrorCode::InvalidTarget)),
            }
        }
        Ok(false)
    }

    /// Exact live client ceiling for one target resource.
    ///
    /// Production repositories return the exact `client_scope` rows belonging
    /// to the resource (plus protocol scopes). In-memory adapters may return
    /// `None`, in which case the already loaded client assignment is used by
    /// unit-level flows only.
    pub async fn client_scopes_for_resource(
        &self,
        client: &OpenIdConnectClient,
        resource_uri: &str,
    ) -> Result<BTreeSet<String>, AppError> {
        if let Some(repo) = &self.resource_repo
            && let Some(codes) = repo
                .client_scope_codes(client.client().oid, resource_uri)
                .await
                .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?
        {
            return Ok(codes.into_iter().collect());
        }
        Ok(client.assigned_scopes().iter().cloned().collect())
    }

    /// Opaque semantic fingerprint of the live client ceiling. Production
    /// derives it from exact `client_scope` rows; the fallback is only for
    /// in-memory adapters without the resource relation.
    pub async fn client_authority_fingerprint(
        &self,
        client: &OpenIdConnectClient,
    ) -> Result<PolicyVersion, AppError> {
        if let Some(repo) = &self.resource_repo
            && let Some(fingerprint) = repo
                .client_authority_fingerprint(client.client().oid)
                .await
                .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?
        {
            return Ok(fingerprint);
        }
        let mut scopes = client.assigned_scopes().to_vec();
        scopes.sort();
        scopes.dedup();
        Ok(PolicyVersion::from_uuid(deterministic_oid(&format!(
            "identity/authorization/client-scope-fallback/v1/{}|{}",
            client.client().oid,
            scopes.join(",")
        ))))
    }

    /// Exact client ceiling for a specific client id without an already loaded
    /// client record. Used by token introspection only after authentication.
    pub async fn client_scopes_for_oid(
        &self,
        client_oid: ClientOid,
        resource_uri: &str,
    ) -> Result<Option<BTreeSet<String>>, AppError> {
        match &self.resource_repo {
            Some(repo) => repo
                .client_scope_codes(client_oid, resource_uri)
                .await
                .map(|codes| codes.map(|codes| codes.into_iter().collect()))
                .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed)),
            None => Ok(None),
        }
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
        self.resolve_scope(scope).await.map(|_| ())
    }

    pub async fn supported_scopes_for_resources(
        &self,
        resources: &[String],
    ) -> Result<Vec<String>, AppError> {
        match &self.scope_catalog {
            Some(repo) => repo
                .list_names_for_resources(resources)
                .await
                .map_err(AppError::internal),
            None => Ok(self.capabilities.scopes_supported.clone()),
        }
    }

    /// Expand selectors only against scopes available to the target resources.
    /// A scope owned by resource B never participates in resource A's wildcard.
    pub async fn resolve_scope_for_resources(
        &self,
        resources: &[String],
        scope: &str,
    ) -> Result<ScopeSet, AppError> {
        ScopeSet::parse(scope).map_err(AppError::map_source(CommonErrorCode::InvalidScope))?;
        let mut supported = self.supported_scopes_for_resources(resources).await?;
        if resources.is_empty() || resources.iter().any(|resource| resource == API_RESOURCE) {
            supported.extend(
                ManagementScope::ALL
                    .into_iter()
                    .map(|item| item.name().to_owned()),
            );
        }
        supported.retain(|name| {
            !is_scope_pattern(name)
                && (!catalog::is_reserved_management_name(name)
                    || ManagementScope::from_name(name).is_some())
        });
        let mut resolved = BTreeSet::new();
        for requested in scope.split(' ').filter(|name| !name.is_empty()) {
            let matches = supported
                .iter()
                .filter(|name| scope_pattern_matches(requested, name));
            let mut found = false;
            for name in matches {
                found = true;
                resolved.insert(name.as_str());
            }
            if !found {
                return Err(AppError::from_code(CommonErrorCode::InvalidScope));
            }
        }
        ScopeSet::parse(&resolved.into_iter().collect::<Vec<_>>().join(" "))
            .map_err(AppError::map_source(CommonErrorCode::InvalidScope))
    }

    /// Expand selectors against the global registered catalog. Callers that know
    /// the target audience should use [`Self::resolve_scope_for_resources`].
    pub async fn resolve_scope(&self, scope: &str) -> Result<ScopeSet, AppError> {
        self.resolve_scope_for_resources(&[], scope).await
    }

    /// Scopes covered by the built-in GraphQL resource when no resource
    /// repository is configured. The trusted management catalog is always
    /// included so management issuance does not depend on a mutable scope row.
    pub(crate) async fn built_in_resource_scopes(&self) -> Result<Vec<String>, AppError> {
        let mut scopes = self.supported_scopes().await?;
        for scope in ManagementScope::ALL {
            if !scopes.iter().any(|name| name == scope.name()) {
                scopes.push(scope.name().to_owned());
            }
        }
        Ok(scopes)
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
