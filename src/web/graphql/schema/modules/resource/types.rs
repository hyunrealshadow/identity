use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, ID, InputObject, MaybeUndefined, Object, Result as GraphqlResult,
};
use chrono::{DateTime, Utc};
use identity_application::authorization::ManagementTarget;
use identity_application::rbac::{ApiResourceRecord, ResourceFilter as ApplicationFilter};
use identity_domain::{authorization::ManagementScope, rbac::ResourceOid};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::super::{
    resource::support::{decode_oid, page_args},
    scope::{
        connection::ScopeConnection,
        query::load_scope_connection,
        types::{ScopeFilter, ScopeOrder},
    },
};
use crate::graphql::schema::{authorization::request_context, management_guard::ManagementGuard};

pub(crate) struct ResourceGlobalId;

impl GlobalIdType for ResourceGlobalId {
    const TYPE_NAME: &'static str = "Resource";
}

pub(crate) fn resource_global_id(oid: ResourceOid) -> ID {
    GlobalId::<ResourceGlobalId>::new(oid.0).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ResourceOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
    #[graphql(name = "NAME_ASC")]
    NameAsc,
    #[graphql(name = "NAME_DESC")]
    NameDesc,
    #[graphql(name = "URI_ASC")]
    UriAsc,
    #[graphql(name = "URI_DESC")]
    UriDesc,
}

impl ResourceOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<ResourceOrder> for identity_application::rbac::ResourceOrder {
    fn from(order: ResourceOrder) -> Self {
        match order {
            ResourceOrder::CreatedAtAsc => Self::CreatedAtAsc,
            ResourceOrder::CreatedAtDesc => Self::CreatedAtDesc,
            ResourceOrder::NameAsc => Self::NameAsc,
            ResourceOrder::NameDesc => Self::NameDesc,
            ResourceOrder::UriAsc => Self::UriAsc,
            ResourceOrder::UriDesc => Self::UriDesc,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct ResourceFilter {
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
    pub enabled: Option<bool>,
}

impl ResourceFilter {
    pub(crate) fn into_application(self) -> ApplicationFilter {
        ApplicationFilter {
            query: self.query,
            enabled: self.enabled,
        }
    }
}

pub(crate) struct ResourceNode {
    id: ID,
    record: ApiResourceRecord,
}

impl ResourceNode {
    pub(crate) fn new(record: ApiResourceRecord) -> Self {
        Self {
            id: resource_global_id(record.oid),
            record,
        }
    }

    pub(crate) fn oid(&self) -> ResourceOid {
        self.record.oid
    }
}

#[Object(name = "Resource")]
impl ResourceNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    async fn uri(&self) -> &str {
        &self.record.uri
    }

    async fn name(&self) -> &str {
        &self.record.name
    }

    async fn enabled(&self) -> bool {
        self.record.enabled
    }

    /// Read-only projection derived from scope rows owned by this resource.
    async fn accepted_scopes(&self) -> &[String] {
        &self.record.accepted_scopes
    }

    /// UUID optimistic-lock version of the resource row.
    async fn version(&self) -> Uuid {
        self.record.version
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }

    /// Canonical scopes owned by this resource. The name is retained for
    /// authorization meaning; nodes are `Scope` identities.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    async fn permissions(
        &self,
        ctx: &Context<'_>,
        filter: Option<ScopeFilter>,
        order_by: Option<ScopeOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<ScopeConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let mut filter = filter.unwrap_or_default();
        filter.resource_id = Some(resource_global_id(self.record.oid));
        load_scope_connection(
            ctx,
            request,
            filter,
            order_by.unwrap_or_else(ScopeOrder::default_order),
            page,
        )
        .await
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateResourceInput {
    #[graphql(validator(chars_min_length = 1, chars_max_length = 2048))]
    pub uri: String,
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: String,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateResourceInput {
    pub id: ID,
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: MaybeUndefined<String>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct ResourceStateInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct ResourcePayload {
    resource_id: ID,
    version: Uuid,
    resource: Option<ResourceNode>,
    client_mutation_id: Option<String>,
}

impl ResourcePayload {
    pub(crate) fn new(record: ApiResourceRecord, client_mutation_id: Option<String>) -> Self {
        Self {
            resource_id: resource_global_id(record.oid),
            version: record.version,
            resource: Some(ResourceNode::new(record)),
            client_mutation_id,
        }
    }
}

#[Object]
impl ResourcePayload {
    async fn resource_id(&self) -> &ID {
        &self.resource_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesRead))
    )]
    async fn resource(&self) -> Option<&ResourceNode> {
        self.resource.as_ref()
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

/// Decode the typed resource ID for one mutation without leaking raw UUIDs.
pub(crate) fn decode_resource_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<ResourceOid> {
    decode_oid::<ResourceGlobalId>(ctx, id).map(ResourceOid)
}
