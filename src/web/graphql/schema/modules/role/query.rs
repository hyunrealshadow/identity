use crate::graphql::schema::access::access;
use async_graphql::{
    Context, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{authorization::ManagementTarget, rbac::EffectivePermissionPageRequest};
use identity_domain::{
    authorization::ManagementScope, openid_connect::ApiScope, rbac::ResourceOid, user::UserOid,
};

use super::{
    connection::{EffectivePermissionConnection, EffectivePermissionEdge},
    integration,
    types::{RoleFilter, RoleNode, RoleOrder, decode_role_oid},
    user_role::{
        AuthorizationSource, EffectivePermissionNode, EffectivePermissionOrder,
        ensure_group_source_read,
    },
};
use crate::graphql::schema::{
    RequestContext,
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    connection,
    connection::ConnectionTotal,
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
    #[allow(clippy::too_many_arguments)]
    async fn roles(
        &self,
        ctx: &Context<'_>,
        filter: Option<RoleFilter>,
        order_by: Option<RoleOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, RoleNode, ConnectionTotal>> {
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

    /// Self-only account summary. This field deliberately carries only the
    /// existing `account.read` self-service scope and accepts no caller-supplied
    /// user identity.
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
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
            None,
            order_by.unwrap_or_else(EffectivePermissionOrder::default_order),
            page,
        )
        .await
    }
}

pub(crate) async fn load_role_connection(
    ctx: &Context<'_>,
    request: &RequestContext,
    filter: RoleFilter,
    order: RoleOrder,
    page: PageArgs,
) -> Result<Connection<RbacConnectionCursor, RoleNode, ConnectionTotal>> {
    let filter = filter.into_application(ctx)?;
    let page = integration::list_roles(request, filter.clone(), order.into(), page)
        .await
        .map_err(|error| app_error(ctx, error))?;
    let additional = connection::connection_total(ctx, async {
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

pub(crate) async fn load_effective_permission_connection(
    ctx: &Context<'_>,
    request: &RequestContext,
    user_oid: UserOid,
    resource_oid: ResourceOid,
    source: Option<AuthorizationSource>,
    order: EffectivePermissionOrder,
    page: PageArgs,
) -> Result<EffectivePermissionConnection> {
    if source.is_some() {
        // Either filter value is derived from group memberships and roles.
        ensure_group_source_read(ctx).await?;
    }
    let source = source.map(Into::into);
    let page = integration::list_effective_permissions(
        request,
        EffectivePermissionPageRequest {
            user_oid,
            resource_oid,
            source,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        },
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let total = connection::connection_total(ctx, async {
        request
            .state
            .services()
            .rbac_management()
            .count_user_permissions(user_oid, resource_oid, source)
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
