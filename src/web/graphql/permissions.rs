use std::collections::BTreeSet;

use async_trait::async_trait;
use identity_application::{authorization::ManagementAccessRequest, error::AppError};

use super::schema::{
    RequestContext,
    authorization::{EffectivePermissionsProvider, EffectivePermissionsView},
};

/// Effective permissions from the live management access service.
pub(super) struct LiveEffectivePermissions;

#[async_trait]
impl EffectivePermissionsProvider for LiveEffectivePermissions {
    async fn effective_permissions(
        &self,
        request: &RequestContext,
    ) -> Result<EffectivePermissionsView, AppError> {
        let snapshot = request
            .claims
            .management
            .as_ref()
            .map(|snapshot| snapshot.to_snapshot())
            .transpose()
            .map_err(AppError::map_internal("graphql.management_snapshot"))?;
        let scopes = request
            .claims
            .scope
            .management_scopes()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let permissions = request
            .state
            .services()
            .management_access()
            .effective_permissions(&ManagementAccessRequest {
                actor: &request.actor,
                principal: request.management_principal(),
                token_scopes: &scopes,
                snapshot: snapshot.as_ref(),
            })
            .await?;
        let names = |scopes: Vec<_>| {
            scopes
                .into_iter()
                .map(|scope: identity_domain::authorization::ManagementScope| {
                    scope.name().to_owned()
                })
                .collect()
        };
        Ok(EffectivePermissionsView {
            requestable_scopes: names(permissions.requestable),
            effective_scopes: names(permissions.effective),
        })
    }
}
