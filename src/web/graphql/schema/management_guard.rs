//! Shared async-graphql guard for forthcoming functional management fields.
use std::collections::BTreeSet;

use super::{access::AccessPolicy, authorization::request_context, error::app_error};
use async_graphql::{Context, Guard, Result};
use identity_application::{
    authorization::{ManagementAccessRequest, ManagementTarget},
    error::codes::authorization,
};
use identity_domain::authorization::ManagementScope;

pub(crate) struct ManagementGuard {
    required: ManagementScope,
    target: ManagementTarget,
}

impl ManagementGuard {
    pub(crate) fn policy(required: ManagementScope) -> AccessPolicy {
        AccessPolicy::management(required)
    }

    pub(crate) const fn new(required: ManagementScope, target: ManagementTarget) -> Self {
        Self { required, target }
    }
}

impl Guard for ManagementGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = request_context(ctx)?;
        let snapshot = request
            .claims
            .management
            .as_ref()
            .map(|snapshot| snapshot.to_snapshot())
            .transpose()
            .map_err(|_| app_error(ctx, authorization::error::AuthorizationSnapshotExpired))?;
        let scopes = request
            .claims
            .scope
            .management_scopes()
            .into_iter()
            .collect::<BTreeSet<_>>();
        request
            .state
            .services()
            .management_access()
            .authorize(
                &ManagementAccessRequest {
                    actor: &request.actor,
                    principal: request.management_principal(),
                    token_scopes: &scopes,
                    snapshot: snapshot.as_ref(),
                },
                self.required,
                self.target,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(())
    }
}
