use crate::graphql::schema::access::access;
use async_graphql::{Context, Enum, ID, InputObject, Object, Result as GraphqlResult};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        ScopeDescription, ScopeFilter as ApplicationFilter, ScopeOid, ScopeOrder as RbacScopeOrder,
        ScopeRecord,
    },
};
use identity_domain::{
    authorization::ManagementScope,
    rbac::{ResourceOid, RoleOid},
};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::super::{
    resource::{
        integration,
        support::{RbacConnectionCursor, decode_oid, page_args},
        types,
        types::{ResourceGlobalId, ResourceNode},
    },
    role::{
        query::load_role_connection,
        types::{RoleFilter, RoleGlobalId, RoleNode, RoleOrder},
    },
};
use crate::graphql::schema::{
    authorization::request_context, connection::ConnectionTotal, error::app_error,
    management_guard::ManagementGuard,
};
use async_graphql::connection::Connection;

pub(crate) struct ScopeGlobalId;

impl GlobalIdType for ScopeGlobalId {
    const TYPE_NAME: &'static str = "Scope";
}

pub(crate) fn scope_global_id(oid: ScopeOid) -> ID {
    GlobalId::<ScopeGlobalId>::new(oid.0).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum ScopeOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
    #[graphql(name = "CODE_ASC")]
    CodeAsc,
    #[graphql(name = "CODE_DESC")]
    CodeDesc,
}

impl ScopeOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<ScopeOrder> for RbacScopeOrder {
    fn from(order: ScopeOrder) -> Self {
        match order {
            ScopeOrder::CreatedAtAsc => Self::CreatedAtAsc,
            ScopeOrder::CreatedAtDesc => Self::CreatedAtDesc,
            ScopeOrder::CodeAsc => Self::CodeAsc,
            ScopeOrder::CodeDesc => Self::CodeDesc,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct ScopeFilter {
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
    pub built_in: Option<bool>,
    pub enabled: Option<bool>,
    pub resource_id: Option<ID>,
    pub role_id: Option<ID>,
    #[graphql(default)]
    pub api_only: bool,
}

impl ScopeFilter {
    pub(crate) fn into_application(self, ctx: &Context<'_>) -> GraphqlResult<ApplicationFilter> {
        let resource_oid = self
            .resource_id
            .as_ref()
            .map(|id| decode_oid::<ResourceGlobalId>(ctx, id))
            .transpose()?
            .map(ResourceOid);
        let role_oid = self
            .role_id
            .as_ref()
            .map(|id| decode_oid::<RoleGlobalId>(ctx, id))
            .transpose()?
            .map(RoleOid);
        Ok(ApplicationFilter {
            query: self.query,
            built_in: self.built_in,
            enabled: self.enabled,
            resource_oid,
            role_oid,
            api_only: self.api_only,
        })
    }
}

pub(crate) struct ScopeDescriptionNode {
    locale: String,
    value: String,
}

impl From<ScopeDescription> for ScopeDescriptionNode {
    fn from(description: ScopeDescription) -> Self {
        Self {
            locale: description.locale,
            value: description.value,
        }
    }
}

#[Object(name = "ScopeDescription")]
impl ScopeDescriptionNode {
    async fn locale(&self) -> &str {
        &self.locale
    }

    async fn value(&self) -> &str {
        &self.value
    }
}

pub(crate) struct ScopeNode {
    id: ID,
    record: ScopeRecord,
}

impl ScopeNode {
    pub(crate) fn new(record: ScopeRecord) -> Self {
        Self {
            id: scope_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "Scope")]
impl ScopeNode {
    #[graphql(complexity = 0)]
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    /// Owning API resource id. `null` marks a protocol/identity scope.
    #[graphql(complexity = 0)]
    async fn resource_id(&self) -> Option<ID> {
        self.record.resource_oid.map(types::resource_global_id)
    }

    /// Stable machine token used in protocol requests and assignments.
    #[graphql(complexity = 0)]
    async fn code(&self) -> &str {
        &self.record.code
    }

    /// Independent fallback name.
    #[graphql(complexity = 0)]
    async fn name(&self) -> &str {
        &self.record.name
    }

    #[graphql(complexity = 0)]
    async fn names(&self) -> Vec<ScopeDescriptionNode> {
        self.record
            .names
            .iter()
            .cloned()
            .map(ScopeDescriptionNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn description(&self) -> &str {
        &self.record.description
    }

    #[graphql(complexity = 0)]
    async fn descriptions(&self) -> Vec<ScopeDescriptionNode> {
        self.record
            .descriptions
            .iter()
            .cloned()
            .map(ScopeDescriptionNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn built_in(&self) -> bool {
        self.record.built_in
    }

    #[graphql(complexity = 0)]
    async fn enabled(&self) -> bool {
        self.record.enabled
    }

    #[graphql(complexity = 0)]
    async fn version(&self) -> Uuid {
        self.record.version
    }

    #[graphql(complexity = 0)]
    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    #[graphql(complexity = 0)]
    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesRead))
    )]
    async fn resource(&self, ctx: &Context<'_>) -> GraphqlResult<Option<ResourceNode>> {
        let Some(oid) = self.record.resource_oid else {
            return Ok(None);
        };
        let request = request_context(ctx)?;
        let resource = integration::find_resource(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(resource.map(ResourceNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn roles(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<Connection<RbacConnectionCursor, RoleNode, ConnectionTotal>> {
        let page = page_args(ctx, first, after, last, before)?;
        load_role_connection(
            ctx,
            request_context(ctx)?,
            RoleFilter {
                scope_id: Some(self.id.clone()),
                ..Default::default()
            },
            RoleOrder::default_order(),
            page,
        )
        .await
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct ScopeDescriptionInput {
    #[graphql(validator(chars_min_length = 1, chars_max_length = 35))]
    pub locale: String,
    #[graphql(validator(chars_max_length = 1024))]
    pub value: String,
}

impl From<ScopeDescriptionInput> for ScopeDescription {
    fn from(description: ScopeDescriptionInput) -> Self {
        Self {
            locale: description.locale,
            value: description.value,
        }
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateScopeInput {
    /// Every custom scope is owned by an API resource.
    pub resource_id: ID,
    #[graphql(validator(chars_min_length = 1, chars_max_length = 128))]
    pub code: String,
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: String,
    #[graphql(default, validator(max_items = 20))]
    pub names: Vec<ScopeDescriptionInput>,
    #[graphql(default, validator(chars_max_length = 1024))]
    pub description: String,
    #[graphql(validator(max_items = 20))]
    pub descriptions: Option<Vec<ScopeDescriptionInput>>,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct ScopeStateInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateScopeInput {
    pub id: ID,
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: Option<String>,
    #[graphql(validator(max_items = 20))]
    pub names: Option<Vec<ScopeDescriptionInput>>,
    #[graphql(validator(chars_max_length = 1024))]
    pub description: Option<String>,
    #[graphql(validator(max_items = 20))]
    pub descriptions: Option<Vec<ScopeDescriptionInput>>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct ScopePayload {
    scope_id: ID,
    version: Uuid,
    scope: Option<ScopeNode>,
    client_mutation_id: Option<String>,
}

impl ScopePayload {
    pub(crate) fn new(record: ScopeRecord, client_mutation_id: Option<String>) -> Self {
        Self {
            scope_id: scope_global_id(record.oid),
            version: record.version,
            scope: Some(ScopeNode::new(record)),
            client_mutation_id,
        }
    }
}

#[Object]
impl ScopePayload {
    async fn scope_id(&self) -> &ID {
        &self.scope_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesRead))
    )]
    async fn scope(&self) -> Option<&ScopeNode> {
        self.scope.as_ref()
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) fn decode_scope_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<ScopeOid> {
    decode_oid::<ScopeGlobalId>(ctx, id).map(ScopeOid)
}
