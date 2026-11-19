use crate::graphql::schema::access::access;
use async_graphql::{Context, ID, Object, Result};
use identity_domain::openid_connect::ApiScope;

use super::{
    access::{
        AccountGroupConnection, AccountPermissionConnection, AccountRoleConnection,
        load_account_groups, load_account_permissions, load_account_roles,
    },
    types::UserNode,
};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    modules::{
        group::types::GroupOrder,
        resource::support::page_args,
        role::user_role::{AuthorizationSource, EffectivePermissionOrder, UserRoleOrder},
    },
};

#[derive(Default)]
pub(crate) struct AccountQuery;

#[Object]
impl AccountQuery {
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserRead))
    )]
    async fn account(&self, ctx: &Context<'_>) -> Result<Option<UserNode>> {
        Ok(Some(UserNode::from(request_context(ctx)?.user()?.clone())))
    }

    /// Active groups the current user belongs to (`user.read` only).
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    async fn account_groups(
        &self,
        ctx: &Context<'_>,
        order_by: Option<GroupOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<AccountGroupConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_account_groups(
            ctx,
            request,
            order_by.unwrap_or_else(GroupOrder::default_order),
            page,
        )
        .await
    }

    /// Active roles currently held by the authenticated user, directly or
    /// inherited through active groups (`user.read` only).
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn account_roles(
        &self,
        ctx: &Context<'_>,
        source: Option<AuthorizationSource>,
        order_by: Option<UserRoleOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<AccountRoleConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_account_roles(
            ctx,
            request,
            source,
            order_by.unwrap_or_else(UserRoleOrder::default_order),
            page,
        )
        .await
    }

    /// Self-only effective permissions across enabled API resources or filtered
    /// to one `resourceId` (`user.read` only).
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn account_permissions(
        &self,
        ctx: &Context<'_>,
        resource_id: Option<ID>,
        source: Option<AuthorizationSource>,
        order_by: Option<EffectivePermissionOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<AccountPermissionConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_account_permissions(
            ctx,
            request,
            resource_id,
            source,
            order_by.unwrap_or_else(EffectivePermissionOrder::default_order),
            page,
        )
        .await
    }
}
