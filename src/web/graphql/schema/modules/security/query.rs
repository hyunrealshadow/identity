use async_graphql::{Context, Object, Result};
use identity_domain::openid_connect::ApiScope;

use super::types::AccountSecurity;
use crate::graphql::schema::{
    authorization::{request_context, require_scope},
    error::app_error,
};

#[derive(Default)]
pub(crate) struct SecurityViewer;

#[Object]
impl SecurityViewer {
    async fn passkeys(&self, ctx: &Context<'_>) -> Result<Vec<PasskeyInfo>> {
        require_scope(ctx, ApiScope::AccountRead)?;
        let request = request_context(ctx)?;
        let keys = request
            .state
            .services()
            .passkey()
            .list(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(keys
            .into_iter()
            .map(|key| PasskeyInfo {
                id: key.id.to_string(),
                name: key.data.name,
            })
            .collect())
    }

    async fn security(&self, ctx: &Context<'_>) -> Result<AccountSecurity> {
        require_scope(ctx, ApiScope::AccountRead)?;
        let request = request_context(ctx)?;
        let status = request
            .state
            .services()
            .mfa()
            .status(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        let passkey_enabled = !request
            .state
            .services()
            .passkey()
            .list(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?
            .is_empty();
        Ok(AccountSecurity::new(
            status.totp_enabled,
            passkey_enabled,
            status.recovery_codes_remaining as i32,
            request.user.preferred_mfa_method,
        ))
    }
}

#[derive(async_graphql::SimpleObject)]
pub(super) struct PasskeyInfo {
    id: String,
    name: String,
}
