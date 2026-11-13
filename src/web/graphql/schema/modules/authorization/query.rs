use crate::graphql::schema::access::{AccessPolicy, access};
use std::sync::Arc;

use async_graphql::{Context, Object, Result, SimpleObject};
use chrono::{DateTime, Utc};
use identity_domain::auth::{
    ACR_AAL2, RECENT_AUTHENTICATION_TTL, acr_satisfies, authentication_is_fresh,
};

use crate::graphql::schema::{
    authorization::{EffectivePermissionsProvider, EffectivePermissionsView, request_context},
    error::app_error,
};

#[derive(Default)]
pub(crate) struct AuthorizationQuery;

#[Object]
impl AuthorizationQuery {
    /// Effective permissions for the current principal. This field only needs
    /// a valid principal: it never requires a management scope, never accepts a
    /// target user and never grants a scope by itself.
    #[graphql(directive = access::apply(AccessPolicy::authenticated()))]
    async fn effective_permissions(&self, ctx: &Context<'_>) -> Result<EffectivePermissions> {
        let request = request_context(ctx)?;
        let view = match ctx.data_opt::<Arc<dyn EffectivePermissionsProvider>>() {
            Some(provider) => provider
                .effective_permissions(request)
                .await
                .map_err(|error| app_error(ctx, error))?,
            None => EffectivePermissionsView {
                requestable_scopes: Vec::new(),
                effective_scopes: Vec::new(),
            },
        };

        let granted_scopes = request
            .claims
            .scope
            .management_scopes()
            .into_iter()
            .map(|scope| scope.name().to_owned())
            .collect();
        let now = Utc::now().timestamp();
        let aal2 = request
            .claims
            .acr
            .as_deref()
            .is_some_and(|acr| acr_satisfies(acr, ACR_AAL2));
        let recent = aal2
            && request.claims.auth_time.is_some_and(|auth_time| {
                authentication_is_fresh(auth_time, now, RECENT_AUTHENTICATION_TTL.as_secs())
            });
        let auth_time = request
            .claims
            .auth_time
            .and_then(|auth_time| DateTime::<Utc>::from_timestamp(auth_time, 0));

        Ok(EffectivePermissions {
            requestable_scopes: view.requestable_scopes,
            granted_scopes,
            effective_scopes: view.effective_scopes,
            authentication: AuthenticationContext {
                acr: request.claims.acr.clone(),
                auth_time,
                aal2,
                recent,
            },
        })
    }
}

#[derive(SimpleObject)]
pub(crate) struct EffectivePermissions {
    requestable_scopes: Vec<String>,
    granted_scopes: Vec<String>,
    effective_scopes: Vec<String>,
    authentication: AuthenticationContext,
}

#[derive(SimpleObject)]
pub(crate) struct AuthenticationContext {
    acr: Option<String>,
    auth_time: Option<DateTime<Utc>>,
    aal2: bool,
    recent: bool,
}
