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
        Ok(AccountSecurity::new(
            status.totp_enabled,
            status.recovery_codes_remaining as i32,
        ))
    }
}
