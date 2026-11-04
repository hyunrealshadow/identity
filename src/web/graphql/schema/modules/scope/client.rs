use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result,
    connection::{Connection, CursorType, Edge, PageInfo},
};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        ClientScopeAssignment, ClientScopeTargetFilter as ApplicationTargetFilter,
        ClientScopeTargetOrder as ApplicationTargetOrder, ClientScopeTargetRecord, ScopeOid,
        SetClientScopesCommand,
    },
};
use identity_domain::{authorization::ManagementScope, client::model::ClientOid};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::{
    super::resource::support::{RbacConnectionCursor, decode_oid, normalize_reason, page_args},
    integration, types,
    types::{ScopeGlobalId, ScopeNode, ScopeOrder},
};
use crate::graphql::schema::{
    authorization::request_context, connection, error::app_error, management_guard::ManagementGuard,
};

pub(crate) struct ClientGlobalId;

impl GlobalIdType for ClientGlobalId {
    const TYPE_NAME: &'static str = "Client";
}

pub(crate) fn client_global_id(oid: ClientOid) -> ID {
    GlobalId::<ClientGlobalId>::new(oid).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ClientScopeTargetOrder {
    #[graphql(name = "NAME_ASC")]
    NameAsc,
    #[graphql(name = "NAME_DESC")]
    NameDesc,
}

impl ClientScopeTargetOrder {
    pub(crate) const fn default_order() -> Self {
        Self::NameAsc
    }
}

impl From<ClientScopeTargetOrder> for ApplicationTargetOrder {
    fn from(order: ClientScopeTargetOrder) -> Self {
        match order {
            ClientScopeTargetOrder::NameAsc => Self::NameAsc,
            ClientScopeTargetOrder::NameDesc => Self::NameDesc,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct ClientScopeTargetFilter {
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
}

impl ClientScopeTargetFilter {
    fn into_application(self) -> ApplicationTargetFilter {
        ApplicationTargetFilter { query: self.query }
    }
}

pub(crate) struct ClientScopeTargetNode {
    record: ClientScopeTargetRecord,
}

impl ClientScopeTargetNode {
    fn new(record: ClientScopeTargetRecord) -> Self {
        Self { record }
    }
}

#[Object(name = "ClientScopeTarget")]
impl ClientScopeTargetNode {
    async fn client_id(&self) -> ID {
        client_global_id(self.record.client_oid)
    }

    async fn name(&self) -> &str {
        &self.record.name
    }

    async fn built_in(&self) -> bool {
        self.record.built_in
    }

    /// Current `client.version` CAS token used by `setClientScopes`.
    async fn version(&self) -> Uuid {
        self.record.version
    }

    async fn allowed_scope_count(&self) -> i32 {
        i32::try_from(self.record.allowed_scope_count).unwrap_or(i32::MAX)
    }
}

#[derive(Default)]
pub(crate) struct ClientScopeQuery;

#[Object]
impl ClientScopeQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn client_scope_targets(
        &self,
        ctx: &Context<'_>,
        filter: Option<ClientScopeTargetFilter>,
        order_by: Option<ClientScopeTargetOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, ClientScopeTargetNode>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let page = integration::list_client_scope_targets(
            request,
            filter.unwrap_or_default().into_application(),
            order_by
                .unwrap_or_else(ClientScopeTargetOrder::default_order)
                .into(),
            page,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
        connection.edges.extend(page.items.into_iter().map(|item| {
            Edge::new(
                RbacConnectionCursor::from_backend(item.cursor),
                ClientScopeTargetNode::new(item.record),
            )
        }));
        Ok(connection)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn client_scopes(
        &self,
        ctx: &Context<'_>,
        client_id: ID,
        order_by: Option<ScopeOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<ClientScopeConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let client_oid = decode_oid::<ClientGlobalId>(ctx, &client_id)?;
        let request = request_context(ctx)?;
        let page = integration::list_client_scopes(
            request,
            client_oid,
            order_by.unwrap_or_else(ScopeOrder::default_order).into(),
            page,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        let additional = connection::connection_total(ctx, async {
            request
                .state
                .services()
                .rbac_management()
                .count_client_scopes(client_oid)
                .await
                .map_err(|error| app_error(ctx, error))
        })
        .await?;
        Ok(ClientScopeConnection {
            edges: page
                .items
                .into_iter()
                .map(|item| ClientScopeEdge {
                    cursor: RbacConnectionCursor::from_backend(item.cursor),
                    client_granted: item.client_granted,
                    node: ScopeNode::new(item.record),
                })
                .collect(),
            has_previous_page: page.has_previous_page,
            has_next_page: page.has_next_page,
            total_count: additional.total_count,
        })
    }
}

/// Scopes assigned to one client. Charged like `ScopeConnection`.
pub(crate) struct ClientScopeConnection {
    edges: Vec<ClientScopeEdge>,
    has_previous_page: bool,
    has_next_page: bool,
    total_count: u64,
}

#[Object]
impl ClientScopeConnection {
    /// Information to aid in pagination.
    #[graphql(complexity = 0)]
    async fn page_info(&self) -> PageInfo {
        PageInfo {
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.edges.first().map(|edge| edge.cursor.encode_cursor()),
            end_cursor: self.edges.last().map(|edge| edge.cursor.encode_cursor()),
        }
    }

    /// A list of edges.
    #[graphql(complexity = "child_complexity")]
    async fn edges(&self) -> &[ClientScopeEdge] {
        &self.edges
    }

    /// A list of nodes.
    #[graphql(complexity = "child_complexity")]
    async fn nodes(&self) -> Vec<&ScopeNode> {
        self.edges.iter().map(|edge| &edge.node).collect()
    }

    #[graphql(complexity = 0)]
    async fn total_count(&self) -> u64 {
        self.total_count
    }
}

pub(crate) struct ClientScopeEdge {
    cursor: RbacConnectionCursor,
    client_granted: bool,
    node: ScopeNode,
}

#[Object]
impl ClientScopeEdge {
    /// The item at the end of the edge
    #[graphql(complexity = "child_complexity")]
    async fn node(&self) -> &ScopeNode {
        &self.node
    }

    /// Whether the client itself holds this scope. Every assignment bounds
    /// requests made on behalf of a user; only granted scopes are available
    /// to client-credentials access.
    #[graphql(complexity = 0)]
    async fn client_granted(&self) -> bool {
        self.client_granted
    }

    /// A cursor for use in pagination
    #[graphql(complexity = 0)]
    async fn cursor(&self) -> String {
        self.cursor.encode_cursor()
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct ClientScopeAssignmentInput {
    pub scope_id: ID,
    /// Grant the scope to the client itself for client-credentials access.
    #[graphql(default)]
    pub client_granted: bool,
}

#[derive(Clone, InputObject)]
pub(crate) struct SetClientScopesInput {
    pub client_id: ID,
    #[graphql(validator(max_items = 1000))]
    pub scopes: Vec<ClientScopeAssignmentInput>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct ClientScopeSetPayload {
    client_id: ID,
    version: Uuid,
    scope_ids: Vec<ID>,
    client_granted_scope_ids: Vec<ID>,
    client_mutation_id: Option<String>,
}

#[Object]
impl ClientScopeSetPayload {
    async fn client_id(&self) -> &ID {
        &self.client_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn scope_ids(&self) -> &[ID] {
        &self.scope_ids
    }

    /// Subset of `scopeIds` granted to the client itself.
    async fn client_granted_scope_ids(&self) -> &[ID] {
        &self.client_granted_scope_ids
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[derive(Default)]
pub(crate) struct ClientScopeMutation;

#[Object]
impl ClientScopeMutation {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsScopes, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsScopes))
    )]
    async fn set_client_scopes(
        &self,
        ctx: &Context<'_>,
        input: SetClientScopesInput,
    ) -> Result<ClientScopeSetPayload> {
        let SetClientScopesInput {
            client_id,
            scopes,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let client_oid = decode_oid::<ClientGlobalId>(ctx, &client_id)?;
        let scopes = scopes
            .iter()
            .map(|assignment| {
                decode_oid::<ScopeGlobalId>(ctx, &assignment.scope_id).map(|oid| {
                    ClientScopeAssignment {
                        scope_oid: ScopeOid(oid),
                        client_granted: assignment.client_granted,
                    }
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::set_client_scopes(
            request,
            SetClientScopesCommand {
                client_oid,
                scopes,
                expected_version,
                reason,
                client_mutation_id: client_mutation_id.clone(),
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ClientScopeSetPayload {
            client_id: client_global_id(result.client_oid),
            version: result.version,
            scope_ids: result
                .scopes
                .iter()
                .map(|assignment| types::scope_global_id(assignment.scope_oid))
                .collect(),
            client_granted_scope_ids: result
                .scopes
                .iter()
                .filter(|assignment| assignment.client_granted)
                .map(|assignment| types::scope_global_id(assignment.scope_oid))
                .collect(),
            client_mutation_id,
        })
    }
}
