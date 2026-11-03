use crate::graphql::schema::access::access;
use async_graphql::{Context, ID, Object, Result};
use identity_application::authorization::ManagementTarget;
use identity_domain::authorization::ManagementScope;

use super::{
    super::resource::support::{PageArgs, RbacConnectionCursor, page_args},
    connection::{ScopeConnection, ScopeEdge},
    integration,
    types::{ScopeFilter, ScopeNode, ScopeOrder, decode_scope_oid},
};
use crate::graphql::schema::{
    RequestContext, authorization::request_context, connection, error::app_error,
    management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct ScopeQuery;

#[Object]
impl ScopeQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesRead))
    )]
    async fn scope(&self, ctx: &Context<'_>, id: ID) -> Result<Option<ScopeNode>> {
        let oid = decode_scope_oid(ctx, &id)?;
        let request = request_context(ctx)?;
        let record = integration::find_scope(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ScopeNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn scopes(
        &self,
        ctx: &Context<'_>,
        filter: Option<ScopeFilter>,
        order_by: Option<ScopeOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<ScopeConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_scope_connection(
            ctx,
            request,
            filter.unwrap_or_default(),
            order_by.unwrap_or_else(ScopeOrder::default_order),
            page,
        )
        .await
    }
}

pub(crate) async fn load_scope_connection(
    ctx: &Context<'_>,
    request: &RequestContext,
    filter: ScopeFilter,
    order: ScopeOrder,
    page: PageArgs,
) -> Result<ScopeConnection> {
    let filter = filter.into_application(ctx)?;
    let page = integration::list_scopes(request, filter.clone(), order.into(), page)
        .await
        .map_err(|error| app_error(ctx, error))?;
    let additional = connection::connection_total(ctx, async {
        request
            .state
            .services()
            .rbac_management()
            .count_scopes(filter)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;
    let mut connection = ScopeConnection::new(
        page.has_previous_page,
        page.has_next_page,
        additional.total_count,
    );
    connection.edges.extend(page.items.into_iter().map(|item| {
        ScopeEdge::new(
            RbacConnectionCursor::from_backend(item.cursor),
            ScopeNode::new(item.record),
        )
    }));
    Ok(connection)
}
