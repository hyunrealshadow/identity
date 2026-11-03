use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Guard, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        GroupMembershipOrder as ApplicationMembershipOrder, GroupMembershipPageRequest,
        GroupOrder as ApplicationGroupOrder, GroupRoleOrder as ApplicationRoleOrder,
        GroupRolePageRequest,
    },
};
use identity_domain::{authorization::ManagementScope, rbac::GroupOid};

use super::{
    integration,
    types::{
        GroupFilter, GroupMembershipFilter as GroupMembershipFilterInput, GroupMembershipNode,
        GroupMembershipOrder, GroupNode, GroupOrder, GroupRoleBindingNode,
        GroupRoleFilter as GroupRoleFilterInput, GroupRoleOrder, decode_group_oid,
    },
};
use crate::graphql::schema::{
    RequestContext,
    authorization::request_context,
    connection,
    connection::ConnectionTotal,
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::support::{PageArgs, RbacConnectionCursor, page_args},
};

#[derive(Default)]
pub(crate) struct GroupQuery;

#[Object]
impl GroupQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead))
    )]
    async fn group(&self, ctx: &Context<'_>, id: ID) -> Result<Option<GroupNode>> {
        let oid = decode_group_oid(ctx, &id)?;
        let request = request_context(ctx)?;
        let record = integration::find_group(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(GroupNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn groups(
        &self,
        ctx: &Context<'_>,
        filter: Option<GroupFilter>,
        order_by: Option<GroupOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, GroupNode, ConnectionTotal>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_group_connection(
            ctx,
            request,
            filter.unwrap_or_default(),
            order_by.unwrap_or_else(GroupOrder::default_order),
            page,
        )
        .await
    }
}

pub(crate) async fn load_group_connection(
    ctx: &Context<'_>,
    request: &RequestContext,
    filter: GroupFilter,
    order: GroupOrder,
    page: PageArgs,
) -> Result<Connection<RbacConnectionCursor, GroupNode, ConnectionTotal>> {
    ensure_relationship_read_guards(ctx, &filter).await?;
    let filter = filter.into_application(ctx)?;
    let page = integration::list_groups(
        request,
        filter.clone(),
        ApplicationGroupOrder::from(order),
        page,
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let additional = connection::connection_total(ctx, async {
        request
            .state
            .services()
            .group_management()
            .count_groups(filter)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;
    let mut connection =
        Connection::with_additional_fields(page.has_previous_page, page.has_next_page, additional);
    connection.edges.extend(page.items.into_iter().map(|item| {
        Edge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            GroupNode::new(item.record),
        )
    }));
    Ok(connection)
}

/// A group list filter that reveals membership or group-role relations needs
/// the corresponding relationship-read authority in addition to `groups.read`.
/// This also covers root compositions such as `User.groups(filter: {roleId})`
/// and `Role.groups(filter: {userId})`.
async fn ensure_relationship_read_guards(ctx: &Context<'_>, filter: &GroupFilter) -> Result<()> {
    if filter.user_id.is_some() {
        ManagementGuard::new(
            ManagementScope::GroupMembershipsRead,
            ManagementTarget::instance(),
        )
        .check(ctx)
        .await?;
    }
    if filter.role_id.is_some() {
        ManagementGuard::new(
            ManagementScope::GroupRolesRead,
            ManagementTarget::instance(),
        )
        .check(ctx)
        .await?;
    }
    Ok(())
}

pub(crate) async fn load_membership_connection(
    ctx: &Context<'_>,
    request: &RequestContext,
    group_oid: GroupOid,
    filter: GroupMembershipFilterInput,
    order: GroupMembershipOrder,
    page: PageArgs,
) -> Result<Connection<RbacConnectionCursor, GroupMembershipNode>> {
    let filter = filter.into_application(ctx)?;
    let page = integration::list_group_memberships(
        request,
        group_oid,
        GroupMembershipPageRequest {
            filter,
            order: ApplicationMembershipOrder::from(order),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        },
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
    connection.edges.extend(page.items.into_iter().map(|item| {
        Edge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            GroupMembershipNode::new(item.record),
        )
    }));
    Ok(connection)
}

pub(crate) async fn load_group_role_connection(
    ctx: &Context<'_>,
    request: &RequestContext,
    group_oid: GroupOid,
    filter: GroupRoleFilterInput,
    order: GroupRoleOrder,
    page: PageArgs,
) -> Result<Connection<RbacConnectionCursor, GroupRoleBindingNode>> {
    let filter = filter.into_application(ctx)?;
    let page = integration::list_group_roles(
        request,
        group_oid,
        GroupRolePageRequest {
            filter,
            order: ApplicationRoleOrder::from(order),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        },
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
    connection.edges.extend(page.items.into_iter().map(|item| {
        Edge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            GroupRoleBindingNode::new(item.record),
        )
    }));
    Ok(connection)
}
