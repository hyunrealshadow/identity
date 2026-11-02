use std::collections::BTreeSet;

use identity_domain::{
    openid_connect::{
        API_RESOURCE, ResourceScopeCoverage, ScopeSet,
        resource::{OAuthResource, valid_resource_uri},
    },
    rbac::{ACCOUNT_SELF_SERVICE_SCOPES, RbacAuthorizationError, STANDARD_OIDC_SCOPES},
};

use crate::{
    error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, common::CommonErrorCode},
    },
    openid_connect::provider::OpenIdProviderService,
};

#[derive(Debug)]
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
        let raw_scope =
            ScopeSet::parse(scope).map_err(AppError::map_source(CommonErrorCode::InvalidScope))?;
        if requested.is_empty() && granted.is_empty() && raw_scope.has_custom_scopes() {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        let default_resources = if requested.is_empty()
            && granted.is_empty()
            && (raw_scope.has_api_scopes() || raw_scope.has_management_scopes())
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
        let parsed_scope = self.resolve_scope_for_resources(&resources, scope).await?;
        let mut allowed = Vec::new();
        let mut rbac_resources = Vec::new();
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
                        scopes: self.built_in_resource_scopes().await?,
                        enabled: true,
                    })
                } else {
                    None
                }
            }
            .filter(|resource| resource.enabled)
            .ok_or_else(|| AppError::from_code(CommonErrorCode::InvalidTarget))?;
            if uri != API_RESOURCE {
                rbac_resources.push(uri.clone());
            }
            allowed.push(
                ScopeSet::parse(&definition.scopes.join(" "))
                    .map_err(|_| AppError::from_code(CommonErrorCode::InvalidTarget))?,
            );
        }
        let scopes = parsed_scope;

        // A business RBAC token has exactly one audience and cannot carry
        // instance-management or account/session self-service scopes. Every
        // business scope must map to an enabled canonical scope row owned by
        // that resource.
        if !rbac_resources.is_empty() {
            if rbac_resources.len() != 1
                || resources.len() != 1
                || scopes.has_management_scopes()
                || scopes.has_api_scopes()
            {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
            let repository = self.rbac_authorization_repo.as_ref().ok_or_else(|| {
                AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable)
            })?;
            let state = repository
                .resource_state(&rbac_resources[0])
                .await
                .map_err(rbac_scope_error)?;
            if !state.enabled {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
            for name in scopes.names() {
                if STANDARD_OIDC_SCOPES.contains(&name) {
                    continue;
                }
                if ACCOUNT_SELF_SERVICE_SCOPES.contains(&name) {
                    return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                }
                let Some(permission) = state.enabled_permission_for_scope(name) else {
                    return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                };
                if permission.resource_oid != state.resource_oid {
                    return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                }
            }
        }

        let selected = scopes.for_resources(&allowed, coverage);
        if scopes.has_resource_permissions() && !selected.has_resource_permissions() {
            return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
        }
        // A flat token scope string cannot distinguish the same resource-owned
        // code granted by two audiences. Fail closed instead of smuggling one
        // resource's code to another.
        if resources.len() > 1 {
            let ambiguous = selected.names().into_iter().any(|name| {
                if STANDARD_OIDC_SCOPES.contains(&name) {
                    return false;
                }
                allowed
                    .iter()
                    .filter(|resource| resource.matches(name))
                    .count()
                    > 1
            });
            if ambiguous {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
        }
        let scope = selected.to_scope_string();
        Ok(ResourceSelection { resources, scope })
    }

    pub async fn validate_authorization_resources(
        &self,
        requested: &[String],
        scope: &ScopeSet,
    ) -> Result<Vec<String>, AppError> {
        if requested.is_empty()
            && (scope.has_api_scopes()
                || scope.has_management_scopes()
                || scope.has_custom_scopes())
        {
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

    /// Exact client ceiling for a selected set of targets. Each non-protocol
    /// scope must belong to the client's rows for the target that owns it.
    pub async fn validate_client_resource_ceiling(
        &self,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        resources: &[String],
        scope: &ScopeSet,
    ) -> Result<(), AppError> {
        let mut ceilings: Vec<BTreeSet<String>> = Vec::with_capacity(resources.len());
        for resource in resources {
            ceilings.push(self.client_scopes_for_resource(client, resource).await?);
        }
        if resources.is_empty() {
            let protocol = if let Some(repo) = &self.resource_repo {
                repo.client_protocol_scope_codes(client.client().oid)
                    .await
                    .map_err(AppError::map_source(CommonErrorCode::ResourceLookupFailed))?
            } else {
                None
            };
            ceilings.push(
                protocol
                    .unwrap_or_else(|| client.assigned_scopes().to_vec())
                    .into_iter()
                    .collect(),
            );
        }
        for name in scope.names() {
            if STANDARD_OIDC_SCOPES.contains(&name) {
                if !ceilings.iter().any(|ceiling| ceiling.contains(name)) {
                    return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                }
                continue;
            }
            let owners = ceilings
                .iter()
                .filter(|ceiling| ceiling.contains(name))
                .count();
            if owners != 1 {
                return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
            }
        }
        Ok(())
    }
}

/// Missing/unusable RBAC state is a safe target error; storage or corrupt
/// state is an internal fail-closed condition. There is no scope-only fallback.
fn rbac_scope_error(error: RbacAuthorizationError) -> AppError {
    match error {
        RbacAuthorizationError::ResourceNotFound => {
            AppError::from_code(CommonErrorCode::InvalidTarget)
        }
        other => {
            AppError::from_code(AuthorizationErrorCode::RbacPolicyUnavailable).with_source(other)
        }
    }
}
