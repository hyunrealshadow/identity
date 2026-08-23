use async_graphql::{Context, Error, ErrorExtensions, Result};
use identity_domain::openid_connect::ApiScope;

use super::context::RequestContext;

pub(super) fn request_context<'a>(ctx: &'a Context<'_>) -> Result<&'a RequestContext> {
    ctx.data::<RequestContext>()
        .map_err(|_| Error::new("authentication context is unavailable"))
}

pub(super) fn require_scope(ctx: &Context<'_>, scope: ApiScope) -> Result<()> {
    if request_context(ctx)?.claims.scope.allows(scope) {
        Ok(())
    } else {
        Err(
            Error::new("insufficient scope").extend_with(|_, extensions| {
                extensions.set("kind", "authorization_error");
                extensions.set("requiredScope", scope.name());
            }),
        )
    }
}

pub(super) fn require_recent_authentication(
    ctx: &Context<'_>,
    required_acr: Option<&str>,
) -> Result<()> {
    let claims = &request_context(ctx)?.claims;
    let now = chrono::Utc::now().timestamp();
    let max_age = if required_acr == Some(identity_domain::auth::ACR_AAL2) {
        identity_domain::auth::ELEVATED_AUTHENTICATION_TTL
    } else {
        identity_domain::auth::RECENT_AUTHENTICATION_TTL
    }
    .as_secs();
    if claims
        .auth_time
        .is_some_and(|auth_time| now.saturating_sub(auth_time) <= max_age as i64)
        && claims.acr.is_some()
        && required_acr.is_none_or(|required| claims.acr.as_deref() == Some(required))
    {
        Ok(())
    } else {
        Err(
            Error::new("recent authentication is required").extend_with(|_, extensions| {
                extensions.set("kind", "authorization_error");
                extensions.set("code", "insufficient_user_authentication");
                extensions.set("max_age", max_age);
                if let Some(required_acr) = required_acr {
                    extensions.set("acr_values", required_acr);
                }
            }),
        )
    }
}
