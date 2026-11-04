use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result as GraphqlResult, connection::Connection,
};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{RoleFilter as RbacRoleFilter, RoleOrder as RbacRoleOrder, RoleRecord, ScopeOid},
};
use identity_domain::{authorization::ManagementScope, rbac::RoleOid};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::super::{
    group::{
        query,
        types::{GroupFilter, GroupNode, GroupOrder, LocalizedTextInput, LocalizedTextNode},
    },
    localized, resource,
    resource::{
        support,
        support::{RbacConnectionCursor, decode_oid, page_args},
    },
    role::user_role::{RoleUserConnection, UserRoleOrder, load_role_users},
    scope::{
        connection::ScopeConnection,
        query::load_scope_connection,
        types::{ScopeFilter, ScopeGlobalId, ScopeOrder, decode_scope_oid},
    },
};
use crate::graphql::schema::{
    authorization::request_context, connection::ConnectionTotal, management_guard::ManagementGuard,
};

pub(crate) struct RoleGlobalId;

impl GlobalIdType for RoleGlobalId {
    const TYPE_NAME: &'static str = "Role";
}

pub(crate) fn role_global_id(oid: RoleOid) -> ID {
    GlobalId::<RoleGlobalId>::new(oid.0).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum RoleOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
    #[graphql(name = "NAME_ASC")]
    NameAsc,
    #[graphql(name = "NAME_DESC")]
    NameDesc,
}

impl RoleOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<RoleOrder> for RbacRoleOrder {
    fn from(order: RoleOrder) -> Self {
        match order {
            RoleOrder::CreatedAtAsc => Self::CreatedAtAsc,
            RoleOrder::CreatedAtDesc => Self::CreatedAtDesc,
            RoleOrder::NameAsc => Self::NameAsc,
            RoleOrder::NameDesc => Self::NameDesc,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct RoleFilter {
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
    pub enabled: Option<bool>,
    pub built_in: Option<bool>,
    /// Optional membership filter on a canonical scope identity.
    pub scope_id: Option<ID>,
}

impl RoleFilter {
    pub(crate) fn into_application(self, ctx: &Context<'_>) -> GraphqlResult<RbacRoleFilter> {
        let scope_oid = self
            .scope_id
            .as_ref()
            .map(|id| decode_scope_oid(ctx, id))
            .transpose()?;
        Ok(RbacRoleFilter {
            query: self.query,
            enabled: self.enabled,
            built_in: self.built_in,
            scope_oid,
        })
    }
}

pub(crate) struct RoleNode {
    id: ID,
    record: RoleRecord,
}

impl RoleNode {
    pub(crate) fn new(record: RoleRecord) -> Self {
        Self {
            id: role_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "Role")]
impl RoleNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    /// Independent default name; clients choose matching translations from `names`.
    async fn name(&self) -> &str {
        &self.record.name
    }

    /// Independent default description; optional translations never overwrite it.
    async fn description(&self) -> &str {
        &self.record.description
    }

    async fn built_in(&self) -> bool {
        self.record.built_in
    }

    async fn names(&self) -> Vec<LocalizedTextNode> {
        localized::names(&self.record.metadata())
    }

    async fn descriptions(&self) -> Vec<LocalizedTextNode> {
        localized::descriptions(&self.record.metadata())
    }

    async fn enabled(&self) -> bool {
        self.record.enabled
    }

    async fn version(&self) -> Uuid {
        self.record.version
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::GroupRolesRead, ManagementTarget::instance()))",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead)),
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupRolesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn groups(
        &self,
        ctx: &Context<'_>,
        filter: Option<GroupFilter>,
        order_by: Option<GroupOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<Connection<RbacConnectionCursor, GroupNode, ConnectionTotal>> {
        let mut filter = filter.unwrap_or_default();
        filter.role_id = Some(self.id.clone());
        let page = support::page_args(ctx, first, after, last, before)?;
        query::load_group_connection(
            ctx,
            request_context(ctx)?,
            filter,
            order_by.unwrap_or_else(GroupOrder::default_order),
            page,
        )
        .await
    }

    /// Scopes explicitly contained by this role. The field name is retained for
    /// authorization meaning; nodes are canonical `Scope` identities.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ScopesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ScopesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
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
        filter.role_id = Some(self.id.clone());
        load_scope_connection(
            ctx,
            request,
            filter,
            order_by.unwrap_or_else(ScopeOrder::default_order),
            page,
        )
        .await
    }

    /// Users assigned this role, with the assignment facts on each edge.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance()))",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn users(
        &self,
        ctx: &Context<'_>,
        enabled: Option<bool>,
        order_by: Option<UserRoleOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<RoleUserConnection> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        load_role_users(
            ctx,
            request,
            self.record.oid,
            enabled,
            order_by.unwrap_or_else(UserRoleOrder::default_order),
            page,
        )
        .await
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateRoleInput {
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: String,
    #[graphql(default, validator(chars_max_length = 1024))]
    pub description: String,
    #[graphql(default, validator(max_items = 20))]
    pub names: Vec<LocalizedTextInput>,
    #[graphql(default, validator(max_items = 20))]
    pub descriptions: Vec<LocalizedTextInput>,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateRoleInput {
    #[graphql(validator(chars_min_length = 1, chars_max_length = 256))]
    pub name: Option<String>,
    #[graphql(validator(chars_max_length = 1024))]
    pub description: Option<String>,
    pub id: ID,
    #[graphql(validator(max_items = 20))]
    pub names: Option<Vec<LocalizedTextInput>>,
    #[graphql(validator(max_items = 20))]
    pub descriptions: Option<Vec<LocalizedTextInput>>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct RoleStateInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct SetRolePermissionsInput {
    pub role_id: ID,
    #[graphql(validator(max_items = 1000))]
    pub permission_ids: Vec<ID>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct RolePayload {
    role_id: ID,
    version: Uuid,
    role: Option<RoleNode>,
    client_mutation_id: Option<String>,
}

impl RolePayload {
    pub(crate) fn new(record: RoleRecord, client_mutation_id: Option<String>) -> Self {
        Self {
            role_id: role_global_id(record.oid),
            version: record.version,
            role: Some(RoleNode::new(record)),
            client_mutation_id,
        }
    }
}

#[Object]
impl RolePayload {
    async fn role_id(&self) -> &ID {
        &self.role_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead))
    )]
    async fn role(&self) -> Option<&RoleNode> {
        self.role.as_ref()
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) fn decode_role_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<RoleOid> {
    decode_oid::<RoleGlobalId>(ctx, id).map(RoleOid)
}

pub(crate) fn decode_scope_ids(ctx: &Context<'_>, ids: &[ID]) -> GraphqlResult<Vec<ScopeOid>> {
    resource::support::decode_oids::<ScopeGlobalId>(ctx, ids)
        .map(|ids| ids.into_iter().map(ScopeOid).collect())
}
