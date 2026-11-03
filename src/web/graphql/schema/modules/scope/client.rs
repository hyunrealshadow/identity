use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        ClientScopeTargetFilter as ApplicationTargetFilter,
        ClientScopeTargetOrder as ApplicationTargetOrder, ClientScopeTargetRecord, ScopeOid,
        SetClientScopesCommand,
    },
};
use identity_domain::{authorization::ManagementScope, client::model::ClientOid};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::{
    super::resource::support::{
        RbacConnectionCursor, decode_oid, decode_oids, normalize_reason, page_args,
    },
    connection::{ScopeConnection, ScopeEdge},
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
    ) -> Result<ScopeConnection> {
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
}

#[derive(Clone, InputObject)]
pub(crate) struct SetClientScopesInput {
    pub client_id: ID,
    #[graphql(validator(max_items = 1000))]
    pub scope_ids: Vec<ID>,
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
            scope_ids,
            expected_version,
            reason,
            client_mutation_id,
        } = input;
        let client_oid = decode_oid::<ClientGlobalId>(ctx, &client_id)?;
        let scope_oids = decode_oids::<ScopeGlobalId>(ctx, &scope_ids)?
            .into_iter()
            .map(ScopeOid)
            .collect();
        let reason = normalize_reason(ctx, &reason)?;
        let request = request_context(ctx)?;
        let result = integration::set_client_scopes(
            request,
            SetClientScopesCommand {
                client_oid,
                scope_oids,
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
                .scope_oids
                .into_iter()
                .map(types::scope_global_id)
                .collect(),
            client_mutation_id,
        })
    }
}
