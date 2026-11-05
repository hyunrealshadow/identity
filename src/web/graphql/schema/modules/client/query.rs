use crate::graphql::schema::access::access;
use async_graphql::{
    Context, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::authorization::ManagementTarget;
use identity_domain::authorization::ManagementScope;

use super::{
    integration,
    types::{ClientFilter, ClientNode, ClientOrder, decode_client_oid},
};
use crate::graphql::schema::{
    authorization::request_context,
    connection,
    connection::ConnectionTotal,
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::support::{RbacConnectionCursor, page_args},
};

#[derive(Default)]
pub(crate) struct ClientQuery;

#[Object]
impl ClientQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead))
    )]
    async fn client(&self, ctx: &Context<'_>, id: ID) -> Result<Option<ClientNode>> {
        let oid = decode_client_oid(ctx, &id)?;
        let record = integration::find_client(request_context(ctx)?, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ClientNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn clients(
        &self,
        ctx: &Context<'_>,
        filter: Option<ClientFilter>,
        order_by: Option<ClientOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, ClientNode, ConnectionTotal>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let filter = filter.unwrap_or_default();
        let page = integration::list_clients(
            request,
            filter.clone().into(),
            order_by.unwrap_or(ClientOrder::CreatedAtDesc).into(),
            page,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        let additional = connection::connection_total(ctx, async {
            integration::count_clients(request, filter.into())
                .await
                .map_err(|error| app_error(ctx, error))
        })
        .await?;
        let mut connection = Connection::with_additional_fields(
            page.has_previous_page,
            page.has_next_page,
            additional,
        );
        connection.edges.extend(page.items.into_iter().map(|item| {
            Edge::new(
                RbacConnectionCursor::from_backend(item.cursor),
                ClientNode::new(item.record),
            )
        }));
        Ok(connection)
    }
}
