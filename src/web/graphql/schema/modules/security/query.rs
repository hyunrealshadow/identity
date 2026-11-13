use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_domain::openid_connect::ApiScope;

use super::types::{AccountSecurity, PasskeyNode};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::app_error,
};

#[derive(Default)]
pub(crate) struct SecurityQuery;

#[Object]
impl SecurityQuery {
    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountRead)))]
    async fn passkeys(&self, ctx: &Context<'_>) -> Result<Vec<PasskeyNode>> {
        let request = request_context(ctx)?;
        let keys = request
            .state
            .services()
            .passkey()
            .list(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(keys.into_iter().map(PasskeyNode::from).collect())
    }

    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountRead)))]
    async fn security(&self, ctx: &Context<'_>) -> Result<AccountSecurity> {
        let request = request_context(ctx)?;
        let status = request
            .state
            .services()
            .mfa()
            .status(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        let passkey_enabled = !request
            .state
            .services()
            .passkey()
            .list(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?
            .is_empty();
        Ok(AccountSecurity::new(
            status.totp_enabled,
            passkey_enabled,
            status.recovery_codes_remaining as i32,
            request.user()?.preferred_mfa_method,
        ))
    }
}
