use crate::graphql::schema::access::access;
use async_graphql::{
    Context, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{EffectivePermissionPageRequest, RoleUserPageRequest, UserRolePageRequest},
};
use identity_domain::{
    authorization::ManagementScope,
    openid_connect::ApiScope,
    rbac::{ResourceOid, RoleOid},
    user::UserOid,
};

use super::{
    binding::{
        EffectivePermissionNode, EffectivePermissionOrder, UserRoleBindingConnectionFields,
        UserRoleBindingNode, UserRoleBindingOrder, decode_user_oid,
    },
    connection::{EffectivePermissionConnection, EffectivePermissionEdge},
    integration,
    types::{RoleFilter, RoleNode, RoleOrder, decode_role_oid},
};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::{
        support::{PageArgs, RbacConnectionCursor, decode_oid, page_args},
        types::ResourceGlobalId,
    },
};

#[derive(Default)]
pub(crate) struct RoleQuery;

#[Object]
impl RoleQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead))
    )]
    async fn role(&self, ctx: &Context<'_>, id: ID) -> Result<Option<RoleNode>> {
        let oid = decode_role_oid(ctx, &id)?;
        let request = request_context(ctx)?;
        let record = integration::find_role(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(RoleNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn roles(
        &self,
        ctx: &Context<'_>,
        filter: Option<RoleFilter>,
        order_by: Option<RoleOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<
        Connection<
            RbacConnectionCursor,
            RoleNode,
            crate::graphql::schema::connection::ConnectionTotal,
        >,
    > {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_role_connection(
            ctx,
            request,
            filter.unwrap_or_default(),
            order_by.unwrap_or_else(RoleOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn user_roles(
        &self,
        ctx: &Context<'_>,
        user_id: ID,
        enabled: Option<bool>,
        order_by: Option<UserRoleBindingOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<
        Connection<RbacConnectionCursor, UserRoleBindingNode, UserRoleBindingConnectionFields>,
    > {
        let page = page_args(ctx, first, after, last, before)?;
        let user_oid = decode_user_oid(ctx, &user_id)?;
        let request = request_context(ctx)?;
        load_binding_connection(
            ctx,
            request,
            BindingTarget::User(user_oid),
            enabled,
            order_by.unwrap_or_else(UserRoleBindingOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn role_users(
        &self,
        ctx: &Context<'_>,
        role_id: ID,
        enabled: Option<bool>,
        order_by: Option<UserRoleBindingOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<
        Connection<RbacConnectionCursor, UserRoleBindingNode, UserRoleBindingConnectionFields>,
    > {
        let page = page_args(ctx, first, after, last, before)?;
        let role_oid = decode_role_oid(ctx, &role_id)?;
        let request = request_context(ctx)?;
        load_binding_connection(
            ctx,
            request,
            BindingTarget::Role(role_oid),
            enabled,
            order_by.unwrap_or_else(UserRoleBindingOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    async fn user_permissions(
        &self,
        ctx: &Context<'_>,
        user_id: ID,
        resource_id: ID,
        order_by: Option<EffectivePermissionOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<EffectivePermissionConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let user_oid = decode_user_oid(ctx, &user_id)?;
        let resource_oid = decode_resource_oid(ctx, &resource_id)?;
        let request = request_context(ctx)?;
        load_effective_permission_connection(
            ctx,
            request,
            user_oid,
            resource_oid,
            order_by.unwrap_or_else(EffectivePermissionOrder::default_order),
            page,
        )
        .await
    }

    /// Self-only account summary. This field deliberately carries only the
    /// existing `account.read` self-service scope and accepts no caller-supplied
    /// user identity.
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    async fn account_permissions(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
        order_by: Option<EffectivePermissionOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<EffectivePermissionConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let user_oid = request.user_oid()?;
        let resource_oid = decode_resource_oid(ctx, &resource_id)?;
        load_effective_permission_connection(
            ctx,
            request,
            user_oid,
            resource_oid,
            order_by.unwrap_or_else(EffectivePermissionOrder::default_order),
            page,
        )
        .await
    }
}

pub(crate) async fn load_role_connection(
    ctx: &Context<'_>,
    request: &crate::graphql::schema::RequestContext,
    filter: RoleFilter,
    order: RoleOrder,
    page: PageArgs,
) -> Result<
    Connection<RbacConnectionCursor, RoleNode, crate::graphql::schema::connection::ConnectionTotal>,
> {
    let filter = filter.into_application(ctx)?;
    let page = integration::list_roles(request, filter.clone(), order.into(), page)
        .await
        .map_err(|error| app_error(ctx, error))?;
    let additional = crate::graphql::schema::connection::connection_total(ctx, async {
        request
            .state
            .services()
            .rbac_management()
            .count_roles(filter)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;
    let mut connection =
        Connection::with_additional_fields(page.has_previous_page, page.has_next_page, additional);
    connection.edges.extend(page.items.into_iter().map(|item| {
        Edge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            RoleNode::new(item.record),
        )
    }));
    Ok(connection)
}

pub(crate) enum BindingTarget {
    User(UserOid),
    Role(RoleOid),
}

pub(crate) async fn load_binding_connection(
    ctx: &Context<'_>,
    request: &crate::graphql::schema::RequestContext,
    target: BindingTarget,
    enabled: Option<bool>,
    order: UserRoleBindingOrder,
    page: PageArgs,
) -> Result<Connection<RbacConnectionCursor, UserRoleBindingNode, UserRoleBindingConnectionFields>>
{
    let page = match target {
        BindingTarget::User(user_oid) => {
            integration::list_user_roles(
                request,
                UserRolePageRequest {
                    user_oid,
                    enabled,
                    order: order.into(),
                    first: page.first,
                    after: page.after,
                    last: page.last,
                    before: page.before,
                },
            )
            .await
        }
        BindingTarget::Role(role_oid) => {
            integration::list_role_users(
                request,
                RoleUserPageRequest {
                    role_oid,
                    enabled,
                    order: order.into(),
                    first: page.first,
                    after: page.after,
                    last: page.last,
                    before: page.before,
                },
            )
            .await
        }
    }
    .map_err(|error| app_error(ctx, error))?;
    // Only `userRoles` has a single target user. `roleUsers`/`Role.users` span
    // several users, so no single current user version is exposed.
    let mut connection = Connection::with_additional_fields(
        page.has_previous_page,
        page.has_next_page,
        UserRoleBindingConnectionFields::new(page.user_version),
    );
    connection.edges.extend(page.items.into_iter().map(|item| {
        Edge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            UserRoleBindingNode::new(item.record),
        )
    }));
    Ok(connection)
}

pub(crate) async fn load_effective_permission_connection(
    ctx: &Context<'_>,
    request: &crate::graphql::schema::RequestContext,
    user_oid: UserOid,
    resource_oid: ResourceOid,
    order: EffectivePermissionOrder,
    page: PageArgs,
) -> Result<EffectivePermissionConnection> {
    let page = integration::list_effective_permissions(
        request,
        EffectivePermissionPageRequest {
            user_oid,
            resource_oid,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        },
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let total = crate::graphql::schema::connection::connection_total(ctx, async {
        request
            .state
            .services()
            .rbac_management()
            .count_user_permissions(user_oid, resource_oid)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;
    let mut connection = EffectivePermissionConnection::new(
        page.has_previous_page,
        page.has_next_page,
        page.user_version,
        total.total_count,
    );
    connection.edges.extend(page.items.into_iter().map(|item| {
        EffectivePermissionEdge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            EffectivePermissionNode::new(item.record),
        )
    }));
    Ok(connection)
}

pub(crate) fn decode_resource_oid(ctx: &Context<'_>, id: &ID) -> Result<ResourceOid> {
    decode_oid::<ResourceGlobalId>(ctx, id).map(ResourceOid)
}
