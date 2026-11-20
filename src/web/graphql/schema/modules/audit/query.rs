use std::collections::{HashMap, HashSet};

use async_graphql::{
    Context, Guard, ID, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{authorization::ManagementTarget, client::ClientRecord};
use identity_domain::{
    authorization::ManagementScope,
    client::model::ClientOid,
    user::{User, UserOid},
};
use uuid::Uuid;

use super::{
    integration,
    types::{AuditEventNode, AuditEventOrder, decode_audit_event_oid},
};
use crate::graphql::schema::{
    access::access,
    authorization::request_context,
    connection::{self, ConnectionTotal},
    error::app_error,
    management_guard::ManagementGuard,
    modules::{
        client,
        resource::support::{RbacConnectionCursor, page_args},
        user,
    },
};

#[derive(Default)]
pub(crate) struct AuditQuery;

#[Object]
impl AuditQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::AuditRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::AuditRead))
    )]
    async fn audit_event(&self, ctx: &Context<'_>, id: ID) -> Result<Option<AuditEventNode>> {
        let oid = decode_audit_event_oid(ctx, &id)?;
        let request = request_context(ctx)?;
        let event = integration::find_event(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(event.map(AuditEventNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::AuditRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::AuditRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn audit_events(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 2048))] query: Option<String>,
        #[graphql(validator(chars_max_length = 100))] time_zone: Option<String>,
        order_by: Option<AuditEventOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, AuditEventNode, ConnectionTotal>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let order = order_by.unwrap_or_else(AuditEventOrder::default_order);

        let result =
            integration::list_events(request, query.clone(), time_zone.clone(), order, page)
                .await
                .map_err(|error| app_error(ctx, error))?;

        let snapshot_at = result.snapshot_at;
        let additional = connection::connection_total(ctx, async {
            integration::count_events(request, query, time_zone, snapshot_at)
                .await
                .map_err(|error| app_error(ctx, error))
        })
        .await?;

        let want_users = connection_selects_field(ctx, "actorUser")
            && ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())
                .check(ctx)
                .await
                .is_ok();
        let want_clients = connection_selects_field(ctx, "actorClient")
            && ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())
                .check(ctx)
                .await
                .is_ok();

        let preloaded_users: HashMap<Uuid, User> = if want_users {
            let user_oids = result
                .items
                .iter()
                .filter(|item| item.event.actor_type.as_deref() == Some("user"))
                .filter_map(|item| item.event.actor_oid.filter(|oid| !oid.is_nil()))
                .collect::<HashSet<_>>()
                .into_iter()
                .map(UserOid)
                .collect::<Vec<_>>();
            if user_oids.is_empty() {
                HashMap::new()
            } else {
                user::integration::find_users(request, user_oids)
                    .await
                    .map_err(|error| app_error(ctx, error))?
                    .into_iter()
                    .map(|user| (user.oid.0, user))
                    .collect()
            }
        } else {
            HashMap::new()
        };

        let preloaded_clients: HashMap<Uuid, ClientRecord> = if want_clients {
            let client_oids: Vec<ClientOid> = result
                .items
                .iter()
                .filter(|item| item.event.actor_type.as_deref() == Some("client"))
                .filter_map(|item| item.event.actor_oid.filter(|oid| !oid.is_nil()))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if client_oids.is_empty() {
                HashMap::new()
            } else {
                client::integration::find_clients(request, client_oids)
                    .await
                    .map_err(|error| app_error(ctx, error))?
                    .into_iter()
                    .map(|record| (record.oid, record))
                    .collect()
            }
        } else {
            HashMap::new()
        };

        let mut connection = Connection::with_additional_fields(
            result.has_previous_page,
            result.has_next_page,
            additional,
        );
        connection
            .edges
            .extend(result.items.into_iter().map(|item| {
                let user = if want_users && item.event.actor_type.as_deref() == Some("user") {
                    item.event
                        .actor_oid
                        .and_then(|oid| preloaded_users.get(&oid).cloned())
                } else {
                    None
                };
                let client = if want_clients && item.event.actor_type.as_deref() == Some("client") {
                    item.event
                        .actor_oid
                        .and_then(|oid| preloaded_clients.get(&oid).cloned())
                } else {
                    None
                };
                Edge::new(
                    RbacConnectionCursor::from_backend(item.cursor),
                    AuditEventNode::with_preloaded_actors(
                        item.event,
                        user,
                        want_users,
                        client,
                        want_clients,
                    ),
                )
            }));
        Ok(connection)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::AuditRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::AuditRead))
    )]
    async fn audit_event_actions(&self, ctx: &Context<'_>) -> Result<Vec<String>> {
        let request = request_context(ctx)?;
        integration::list_distinct_actions(request)
            .await
            .map_err(|error| app_error(ctx, error))
    }
}

fn connection_selects_field(ctx: &Context<'_>, field_name: &str) -> bool {
    let look_ahead = ctx.look_ahead();
    look_ahead
        .field("edges")
        .field("node")
        .field(field_name)
        .exists()
        || look_ahead.field("nodes").field(field_name).exists()
}

#[cfg(test)]
mod tests {
    use async_graphql::{EmptySubscription, Request, Schema};

    use crate::graphql::schema::modules::{MutationRoot, QueryRoot};

    #[tokio::test]
    async fn schema_allows_audit_events_with_all_console_fields_at_first_100_within_complexity_limit()
     {
        let schema = Schema::build(
            QueryRoot::default(),
            MutationRoot::default(),
            EmptySubscription,
        )
        .limit_complexity(3000)
        .limit_depth(16)
        .finish();

        // Execute complexity analyzer on full Console AuditEventsQuery at first: 100.
        // Without a RequestContext it fails inside resolver AFTER complexity/depth validation passes,
        // so any complexity > 3000 would surface as a GraphQL parse/validation complexity error.
        let query = r#"
            query {
                auditEvents(first: 100, query: "action:user.*", timeZone: "Asia/Shanghai", orderBy: OCCURRED_AT_DESC) {
                    totalCount
                    pageInfo {
                        hasPreviousPage
                        hasNextPage
                        startCursor
                        endCursor
                    }
                    edges {
                        cursor
                        node {
                            id
                            occurredAt
                            transactionId
                            action
                            operation
                            eventKind
                            actorType
                            actorOid
                            actorGlobalId
                            targetType
                            targetOid
                            targetGlobalId
                            resourceType
                            resourceOid
                            resourceGlobalId
                            subjectOid
                            subjectGlobalId
                            status
                            previousStatus
                            credentialType
                            reason
                            requestId
                            traceId
                            actorUser {
                                id
                                username
                                email
                                nickname
                            }
                            actorClient {
                                id
                                name
                                names {
                                    locale
                                    value
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let response = schema.execute(Request::new(query)).await;
        assert!(
            !response
                .errors
                .iter()
                .any(|err| err.message.contains("complex")),
            "unexpected complexity rejection at first=100: {:?}",
            response.errors
        );
    }
}
