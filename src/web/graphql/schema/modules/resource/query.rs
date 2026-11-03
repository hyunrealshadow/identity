use crate::graphql::schema::access::access;
use async_graphql::{
    Context, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::authorization::ManagementTarget;
use identity_domain::authorization::ManagementScope;

use super::{
    integration,
    support::{RbacConnectionCursor, page_args},
    types::{ResourceFilter, ResourceNode, ResourceOrder, decode_resource_oid},
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct ResourceQuery;

#[Object]
impl ResourceQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesRead))
    )]
    async fn resource(&self, ctx: &Context<'_>, id: ID) -> Result<Option<ResourceNode>> {
        let oid = decode_resource_oid(ctx, &id)?;
        let request = request_context(ctx)?;
        let record = integration::find_resource(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ResourceNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn resources(
        &self,
        ctx: &Context<'_>,
        filter: Option<ResourceFilter>,
        order_by: Option<ResourceOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, ResourceNode>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let page = integration::list_resources(
            request,
            filter.unwrap_or_default().into_application(),
            order_by.unwrap_or_else(ResourceOrder::default_order).into(),
            page,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;

        let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
        connection.edges.extend(page.items.into_iter().map(|item| {
            Edge::new(
                RbacConnectionCursor::from_backend(item.cursor),
                ResourceNode::new(item.record),
            )
        }));
        Ok(connection)
    }
}
