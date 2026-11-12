use async_graphql::{
    Context, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{
    authorization::ManagementTarget, key::management::ManagedKeyPageRequest,
};
use identity_domain::authorization::ManagementScope;

use super::types::{KeyFilter, KeyNode, SigningKeyAlgorithm};
use crate::graphql::schema::{
    access::access,
    authorization::request_context,
    connection::{self, ConnectionTotal},
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::support::{RbacConnectionCursor, page_args},
};

#[derive(Default)]
pub(crate) struct KeyQuery;

#[Object]
impl KeyQuery {
    /// JWA algorithms a signing key can be added with, and the key each one
    /// generates.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRead))
    )]
    async fn signing_key_algorithms(&self) -> Vec<SigningKeyAlgorithm> {
        identity_application::key::management::signing_key_algorithms()
            .into_iter()
            .map(SigningKeyAlgorithm::from)
            .collect()
    }

    /// Signing and data encryption keys, newest first.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn keys(
        &self,
        ctx: &Context<'_>,
        filter: Option<KeyFilter>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, KeyNode, ConnectionTotal>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let filter = filter.unwrap_or_default().into_application();
        let service = request.state.services().key_management();
        let result = service
            .list(ManagedKeyPageRequest {
                filter: filter.clone(),
                first: page.first,
                after: page.after,
                last: page.last,
                before: page.before,
            })
            .await
            .map_err(|error| app_error(ctx, error))?;
        let additional = connection::connection_total(ctx, async {
            service
                .count(filter)
                .await
                .map_err(|error| app_error(ctx, error))
        })
        .await?;
        let mut connection = Connection::with_additional_fields(
            result.has_previous_page,
            result.has_next_page,
            additional,
        );
        connection
            .edges
            .extend(result.items.into_iter().map(|item| {
                Edge::new(
                    RbacConnectionCursor::from_backend(item.cursor),
                    KeyNode::new(item.view),
                )
            }));
        Ok(connection)
    }
}
