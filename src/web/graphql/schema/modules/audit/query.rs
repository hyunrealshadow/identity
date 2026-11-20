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

use identity_domain::audit as domain;

use super::{
    enums::AuditCategory,
    integration,
    types::{AuditEventNode, AuditEventOrder, PreloadedActor, decode_audit_event_oid},
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
        category: Option<AuditCategory>,
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

        let category = category.map(domain::AuditCategory::from);
        let result = integration::list_events(
            request,
            category,
            query.clone(),
            time_zone.clone(),
            order,
            page,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;

        let snapshot_at = result.snapshot_at;
        let additional = connection::connection_total(ctx, async {
            integration::count_events(request, category, query, time_zone, snapshot_at)
                .await
                .map_err(|error| app_error(ctx, error))
        })
        .await?;

        let want_users = connection_selects_actor(ctx, "user")
            && ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())
                .check(ctx)
                .await
                .is_ok();
        let want_clients = connection_selects_actor(ctx, "client")
            && ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())
                .check(ctx)
                .await
                .is_ok();

        let preloaded_users: HashMap<Uuid, User> = if want_users {
            let user_oids = result
                .items
                .iter()
                .filter(|item| item.event.actor.kind == domain::AuditActorKind::User)
                .filter_map(|item| item.event.actor.oid)
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
                .filter(|item| item.event.actor.kind == domain::AuditActorKind::Client)
                .filter_map(|item| item.event.actor.oid)
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
                let actor = &item.event.actor;
                let preloaded = PreloadedActor {
                    user: actor
                        .oid
                        .filter(|_| actor.kind == domain::AuditActorKind::User)
                        .and_then(|oid| preloaded_users.get(&oid).cloned()),
                    user_loaded: want_users,
                    client: actor
                        .oid
                        .filter(|_| actor.kind == domain::AuditActorKind::Client)
                        .and_then(|oid| preloaded_clients.get(&oid).cloned()),
                    client_loaded: want_clients,
                };
                Edge::new(
                    RbacConnectionCursor::from_backend(item.cursor),
                    AuditEventNode::with_preloaded_actor(item.event, preloaded),
                )
            }));
        Ok(connection)
    }
}

fn connection_selects_actor(ctx: &Context<'_>, field_name: &str) -> bool {
    let look_ahead = ctx.look_ahead();
    look_ahead
        .field("edges")
        .field("node")
        .field("actor")
        .field(field_name)
        .exists()
        || look_ahead
            .field("nodes")
            .field("actor")
            .field(field_name)
            .exists()
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
                auditEvents(first: 100, category: MANAGEMENT, query: "action:user_*", timeZone: "Asia/Shanghai", orderBy: OCCURRED_AT_DESC) {
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
                            category
                            action
                            outcome
                            failureReason
                            actor {
                                kind
                                id
                                oid
                                label
                                user {
                                    id
                                    username
                                    email
                                    nickname
                                }
                                client {
                                    id
                                    name
                                    names {
                                        locale
                                        value
                                    }
                                }
                            }
                            target {
                                kind
                                id
                                oid
                                label
                            }
                            clientId
                            authMethods
                            ipAddress
                            userAgent
                            requestId
                            traceId
                            changes {
                                field
                                kind
                                oldValue
                                newValue
                                added
                                removed
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
