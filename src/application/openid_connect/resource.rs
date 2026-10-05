use crate::error::{AppError, codes::common::CommonErrorCode};
use crate::openid_connect::provider::OpenIdProviderService;
use identity_domain::openid_connect::resource::{OAuthResource, valid_resource_uri};
use identity_domain::openid_connect::{API_RESOURCE, ResourceScopeCoverage, ScopeSet};

pub struct ResourceSelection {
    pub resources: Vec<String>,
    pub scope: String,
}

impl OpenIdProviderService {
    /// Resolve the access-token targets, constrained by an explicit original grant.
    pub async fn select_resources(
        &self,
        requested: &[String],
        granted: &[String],
        scope: &str,
    ) -> Result<ResourceSelection, AppError> {
        self.resolve_resources(requested, granted, scope, ResourceScopeCoverage::All)
            .await
    }

    async fn resolve_resources(
        &self,
        requested: &[String],
        granted: &[String],
        scope: &str,
        coverage: ResourceScopeCoverage,
    ) -> Result<ResourceSelection, AppError> {
        self.validate_scope_names(scope).await?;
        let parsed_scope = ScopeSet::parse(scope)
            .map_err(|_| AppError::from_code(CommonErrorCode::InvalidScope))?;
        if requested.is_empty() && granted.is_empty() && parsed_scope.has_custom_scopes() {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        let default_resources = if requested.is_empty()
            && granted.is_empty()
            && ScopeSet::parse(scope).is_ok_and(|scope| scope.has_api_scopes())
        {
            vec![API_RESOURCE.to_owned()]
        } else {
            Vec::new()
        };
        let mut resources = Vec::new();
        for uri in if requested.is_empty() {
            granted
        } else {
            requested
        } {
            if !valid_resource_uri(uri)
                || (!requested.is_empty() && !granted.is_empty() && !granted.contains(uri))
            {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
            if !resources.contains(uri) {
                resources.push(uri.clone());
            }
        }
        if resources.is_empty() {
            resources = default_resources;
        }
        if resources.is_empty() {
            return Ok(ResourceSelection {
                resources,
                scope: scope.to_owned(),
            });
        }
        let mut allowed = Vec::new();
        for uri in &resources {
            let definition = if let Some(repo) = &self.resource_repo {
                repo.find_by_uri(uri)
                    .await
                    .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?
            } else {
                // Standalone providers retain the built-in resource; production injects the DB store.
                if uri == API_RESOURCE {
                    Some(OAuthResource {
                        uri: uri.clone(),
                        scopes: self.supported_scopes().await?,
                        enabled: true,
                    })
                } else {
                    None
                }
            }
            .filter(|resource| resource.enabled)
            .ok_or_else(|| AppError::from_code(CommonErrorCode::InvalidTarget))?;
            allowed.push(
                ScopeSet::parse(&definition.scopes.join(" "))
                    .map_err(|_| AppError::from_code(CommonErrorCode::InvalidTarget))?,
            );
        }
        let scopes = ScopeSet::parse(scope)
            .map_err(|_| AppError::from_code(CommonErrorCode::InvalidTarget))?;
        let selected = scopes.for_resources(&allowed, coverage);
        if scopes.has_resource_permissions() && !selected.has_resource_permissions() {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        let scope = selected.to_scope_string();
        Ok(ResourceSelection { resources, scope })
    }

    pub async fn validate_authorization_resources(
        &self,
        requested: &[String],
        scope: &ScopeSet,
    ) -> Result<Vec<String>, AppError> {
        if requested.is_empty() && (scope.has_api_scopes() || scope.has_custom_scopes()) {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        let original = scope.to_scope_string();
        let selection = self
            .resolve_resources(requested, &[], &original, ResourceScopeCoverage::Any)
            .await?;
        if selection.scope != original {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        Ok(selection.resources)
    }
}
