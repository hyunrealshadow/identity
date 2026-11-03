//! Read-authority decisions for management user metadata.
//!
//! Management metadata on the `User` type is never implied by constructing a
//! user from a write result or from the self-service account service. It always
//! requires `management.user.read`; the Node lookup additionally preserves the
//! existing `account.read` self-only fallback.

use async_graphql::{Context, Error, Guard, Result, Value};
use identity_application::authorization::ManagementTarget;
use identity_domain::{authorization::ManagementScope, openid_connect::ApiScope, user::UserOid};

use crate::graphql::schema::{
    RequestContext, authorization::request_context, management_guard::ManagementGuard,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserReadAccess {
    /// The caller proved a live `management.user.read` authority for the target.
    Management,
    /// The caller may read only its own account through `account.read`.
    SelfOnly,
}

pub(crate) async fn ensure_user_management_read(ctx: &Context<'_>, target: UserOid) -> Result<()> {
    ManagementGuard::new(
        ManagementScope::UsersRead,
        ManagementTarget::user(target, false),
    )
    .check(ctx)
    .await
}

fn has_management_users_read(request: &RequestContext) -> bool {
    request
        .claims
        .scope
        .management_scopes()
        .contains(&ManagementScope::UsersRead)
}

/// Decide how a Node/nodes User lookup may read the target.
///
/// Explicit management read wins when it is valid. For one's own ID, the
/// pre-existing `account.read` self-only path remains available. A genuine
/// policy denial on the management path is allowed to fall back to that
/// self-only path; infrastructure/internal failures are propagated instead of
/// being misreported as a self-service read.
pub(crate) async fn node_user_read_access(
    ctx: &Context<'_>,
    target: UserOid,
) -> Result<UserReadAccess> {
    let request = request_context(ctx)?;
    let is_self = request.claims.user_oid == Some(target);
    let self_read = is_self && request.claims.scope.allows(ApiScope::AccountRead);

    if !self_read {
        ensure_user_management_read(ctx, target).await?;
        return Ok(UserReadAccess::Management);
    }

    if !has_management_users_read(request) {
        return Ok(UserReadAccess::SelfOnly);
    }

    match ensure_user_management_read(ctx, target).await {
        Ok(()) => Ok(UserReadAccess::Management),
        Err(error) if is_authorization_denial(&error) => Ok(UserReadAccess::SelfOnly),
        Err(error) => Err(error),
    }
}

fn is_authorization_denial(error: &Error) -> bool {
    matches!(
        error
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("kind")),
        Some(Value::String(kind))
            if kind.as_str() == "forbidden" || kind.as_str() == "unauthorized"
    )
}
