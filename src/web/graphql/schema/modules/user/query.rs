use crate::graphql::schema::access::access;
use async_graphql::{
    Context, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{
    authorization::ManagementTarget,
    error::{codes::graphql::GraphqlErrorCode, params::ErrorParams},
};
use identity_domain::{authorization::ManagementScope, user::UserOid};
use identity_infrastructure::graphql::id::GlobalId;

use super::{
    cursor::UserConnectionCursor,
    integration,
    types::{UserFilter, UserOrder},
};
use crate::graphql::schema::{
    authorization::request_context,
    connection,
    connection::ConnectionTotal,
    error::{app_error, coded_error},
    management_guard::ManagementGuard,
    modules::account::{UserGlobalId, UserNode},
};

#[derive(Default)]
pub(crate) struct UserManagementQuery;

#[Object]
impl UserManagementQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn user(&self, ctx: &Context<'_>, id: ID) -> Result<Option<UserNode>> {
        let oid = decode_user_oid(ctx, &id)?;
        let request = request_context(ctx)?;
        let record = integration::find_user(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(UserNode::managed))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn users(
        &self,
        ctx: &Context<'_>,
        filter: Option<UserFilter>,
        order_by: Option<UserOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<UserConnectionCursor, UserNode, ConnectionTotal>> {
        let request = request_context(ctx)?;
        let filter = filter.unwrap_or_default();
        let page = integration::list_users(
            request,
            filter.clone(),
            order_by.unwrap_or_else(UserOrder::default_order),
            first.map(|value| value as u32),
            after,
            last.map(|value| value as u32),
            before,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;

        let additional = connection::connection_total(ctx, async {
            integration::count_users(request, filter)
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
                UserConnectionCursor::from_backend(item.cursor),
                UserNode::managed(item.user),
            )
        }));
        Ok(connection)
    }
}

pub(super) fn decode_user_oid(ctx: &Context<'_>, id: &ID) -> Result<UserOid> {
    let oid = GlobalId::<UserGlobalId>::try_from(id)
        .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))?
        .oid();
    Ok(UserOid(oid))
}
