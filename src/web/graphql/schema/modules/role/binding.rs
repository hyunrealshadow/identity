use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, Guard, GuardExt, ID, InputObject, Object, Result as GraphqlResult,
};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        EffectiveGroupPermissionSourceRecord,
        EffectivePermissionOrder as RbacEffectivePermissionOrder, EffectivePermissionRecord,
        EffectivePermissionSourceRecord, ScopeOid, UserRoleBindingMutationResult,
        UserRoleBindingOrder as RbacUserRoleBindingOrder, UserRoleBindingRecord,
    },
};
use identity_domain::{
    authorization::ManagementScope, openid_connect::ApiScope, rbac::UserRoleBindingOid,
    user::UserOid,
};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::{
    super::{
        account::{UserGlobalId, UserNode},
        group::{integration as group_integration, types as group_types, types::GroupNode},
        resource::{support::decode_oid, types as resource_types},
        role::{integration, types::RoleNode},
        scope::types as scope_types,
    },
    types,
};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::app_error,
    management_guard::ManagementGuard,
    modules::user::integration as user_integration,
};

/// Bound for server-produced binding IDs expanded by a mutation payload.
const MAX_PAYLOAD_BINDINGS: usize = 100;

pub(crate) struct BindingGlobalId;

impl GlobalIdType for BindingGlobalId {
    const TYPE_NAME: &'static str = "UserRoleBinding";
}

pub(crate) fn binding_global_id(oid: UserRoleBindingOid) -> ID {
    GlobalId::<BindingGlobalId>::new(oid.0).into()
}

fn user_global_id(oid: UserOid) -> ID {
    GlobalId::<UserGlobalId>::new(oid.0).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum UserRoleBindingOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
}

impl UserRoleBindingOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<UserRoleBindingOrder> for RbacUserRoleBindingOrder {
    fn from(order: UserRoleBindingOrder) -> Self {
        match order {
            UserRoleBindingOrder::CreatedAtAsc => Self::CreatedAtAsc,
            UserRoleBindingOrder::CreatedAtDesc => Self::CreatedAtDesc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum EffectivePermissionOrder {
    #[graphql(name = "CODE_ASC")]
    CodeAsc,
    #[graphql(name = "CODE_DESC")]
    CodeDesc,
}

impl EffectivePermissionOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CodeAsc
    }
}

impl From<EffectivePermissionOrder> for RbacEffectivePermissionOrder {
    fn from(order: EffectivePermissionOrder) -> Self {
        match order {
            EffectivePermissionOrder::CodeAsc => Self::CodeAsc,
            EffectivePermissionOrder::CodeDesc => Self::CodeDesc,
        }
    }
}

/// Additional connection field for `userRoles`/`roleUsers`.
///
/// It is nullable because a multi-user list has no single current user
/// version. `userRoles` returns the server value even for an empty page.
pub(crate) struct UserRoleBindingConnectionFields {
    user_version: Option<Uuid>,
}

impl UserRoleBindingConnectionFields {
    pub(crate) const fn new(user_version: Option<Uuid>) -> Self {
        Self { user_version }
    }
}

#[Object(name = "UserRoleBindingConnectionFields")]
impl UserRoleBindingConnectionFields {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead))
    )]
    async fn user_version(&self) -> Option<Uuid> {
        self.user_version
    }
}

pub(crate) struct EffectivePermissionVersionGuard;

impl Guard for EffectivePermissionVersionGuard {
    async fn check(&self, ctx: &Context<'_>) -> GraphqlResult<()> {
        if ManagementGuard::new(
            ManagementScope::RoleAssignmentsRead,
            ManagementTarget::instance(),
        )
        .check(ctx)
        .await
        .is_ok()
        {
            return Ok(());
        }
        UserPrincipalGuard
            .and(ScopeGuard::new(ApiScope::AccountRead))
            .check(ctx)
            .await
    }
}

pub(crate) struct UserRoleBindingNode {
    id: ID,
    record: UserRoleBindingRecord,
}

impl UserRoleBindingNode {
    pub(crate) fn new(record: UserRoleBindingRecord) -> Self {
        Self {
            id: binding_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "UserRoleBinding")]
impl UserRoleBindingNode {
    async fn id(&self) -> &ID {
        &self.id
    }

    async fn user_id(&self) -> ID {
        user_global_id(self.record.user_oid)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn user(&self, ctx: &Context<'_>) -> GraphqlResult<Option<UserNode>> {
        let request = request_context(ctx)?;
        let record = user_integration::find_user(request, self.record.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(UserNode::managed))
    }

    async fn role_id(&self) -> ID {
        types::role_global_id(self.record.role_oid)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead))
    )]
    async fn role(&self, ctx: &Context<'_>) -> GraphqlResult<Option<RoleNode>> {
        let request = request_context(ctx)?;
        let record = integration::find_role(request, self.record.role_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(RoleNode::new))
    }

    async fn granted_by_user_id(&self) -> Option<ID> {
        self.record.granted_by_user_oid.map(user_global_id)
    }

    async fn reason(&self) -> &str {
        &self.record.reason
    }

    async fn enabled(&self) -> bool {
        self.record.enabled
    }

    async fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.record.revoked_at
    }

    async fn version(&self) -> Uuid {
        self.record.version
    }

    async fn user_version(&self) -> Uuid {
        self.record.user_version
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }
}

pub(crate) struct EffectivePermissionSourceNode {
    record: EffectivePermissionSourceRecord,
}

impl From<EffectivePermissionSourceRecord> for EffectivePermissionSourceNode {
    fn from(record: EffectivePermissionSourceRecord) -> Self {
        Self { record }
    }
}

#[Object(name = "EffectivePermissionSource")]
impl EffectivePermissionSourceNode {
    #[graphql(complexity = 0)]
    async fn binding_id(&self) -> ID {
        binding_global_id(self.record.binding_oid)
    }

    #[graphql(complexity = 0)]
    async fn role_id(&self) -> ID {
        types::role_global_id(self.record.role_oid)
    }
}

pub(crate) struct EffectivePermissionNode {
    record: EffectivePermissionRecord,
}

pub(crate) struct EffectiveGroupPermissionSourceNode {
    record: EffectiveGroupPermissionSourceRecord,
}

impl From<EffectiveGroupPermissionSourceRecord> for EffectiveGroupPermissionSourceNode {
    fn from(record: EffectiveGroupPermissionSourceRecord) -> Self {
        Self { record }
    }
}

#[Object(name = "EffectiveGroupPermissionSource")]
impl EffectiveGroupPermissionSourceNode {
    #[graphql(complexity = 0)]
    async fn group_id(&self) -> ID {
        group_types::group_global_id(self.record.group_oid)
    }

    #[graphql(complexity = 0)]
    async fn membership_id(&self) -> ID {
        group_types::membership_global_id(self.record.membership_oid)
    }

    #[graphql(complexity = 0)]
    async fn group_role_binding_id(&self) -> ID {
        group_types::group_role_global_id(self.record.group_role_binding_oid)
    }

    #[graphql(complexity = 0)]
    async fn role_id(&self) -> ID {
        types::role_global_id(self.record.role_oid)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead))
    )]
    async fn group(&self, ctx: &Context<'_>) -> GraphqlResult<Option<GroupNode>> {
        let record = group_integration::find_group(request_context(ctx)?, self.record.group_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(GroupNode::new))
    }
}

impl EffectivePermissionNode {
    pub(crate) fn new(record: EffectivePermissionRecord) -> Self {
        Self { record }
    }
}

#[Object(name = "EffectivePermission")]
impl EffectivePermissionNode {
    /// Canonical `Scope` identity; the field name retains authorization meaning.
    #[graphql(complexity = 0)]
    async fn permission_id(&self) -> ID {
        scope_types::scope_global_id(ScopeOid(self.record.permission_oid.0))
    }

    #[graphql(complexity = 0)]
    async fn resource_id(&self) -> ID {
        resource_types::resource_global_id(self.record.resource_oid)
    }

    #[graphql(complexity = 0)]
    async fn code(&self) -> &str {
        &self.record.code
    }

    #[graphql(complexity = 0)]
    async fn scope(&self) -> &str {
        &self.record.scope
    }

    #[graphql(complexity = 0)]
    async fn sources(&self) -> Vec<EffectivePermissionSourceNode> {
        self.record
            .sources
            .iter()
            .cloned()
            .map(EffectivePermissionSourceNode::from)
            .collect()
    }

    #[graphql(
        complexity = "child_complexity",
        guard = "ManagementGuard::new(ManagementScope::GroupMembershipsRead, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::GroupRolesRead, ManagementTarget::instance()))",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupMembershipsRead)),
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupRolesRead))
    )]
    async fn group_sources(&self) -> Vec<EffectiveGroupPermissionSourceNode> {
        self.record
            .group_sources
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }
}

pub(crate) struct UserRoleBindingPayload {
    user_id: ID,
    user_version: Uuid,
    binding_ids: Vec<ID>,
    binding_oids: Vec<UserRoleBindingOid>,
    created_count: i32,
    revoked_count: i32,
    client_mutation_id: Option<String>,
}

impl UserRoleBindingPayload {
    pub(crate) fn new(
        result: UserRoleBindingMutationResult,
        client_mutation_id: Option<String>,
    ) -> Self {
        let user_id = user_global_id(result.user_oid);
        let binding_ids = result
            .binding_oids
            .iter()
            .copied()
            .map(binding_global_id)
            .collect();
        Self {
            user_id,
            user_version: result.user_version,
            binding_ids,
            binding_oids: result.binding_oids,
            created_count: i32::try_from(result.created_count).unwrap_or(i32::MAX),
            revoked_count: i32::try_from(result.revoked_count).unwrap_or(i32::MAX),
            client_mutation_id,
        }
    }
}

#[Object]
impl UserRoleBindingPayload {
    async fn user_id(&self) -> &ID {
        &self.user_id
    }

    async fn user_version(&self) -> Uuid {
        self.user_version
    }

    async fn binding_ids(&self) -> &[ID] {
        &self.binding_ids
    }

    async fn created_count(&self) -> i32 {
        self.created_count
    }

    async fn revoked_count(&self) -> i32 {
        self.revoked_count
    }

    /// Expanded bindings for the server-produced IDs returned by this
    /// mutation. Scalar payload fields stay unguarded so a writer without read
    /// authority can still confirm the write; only this read object is guarded.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead))
    )]
    async fn bindings(&self, ctx: &Context<'_>) -> GraphqlResult<Option<Vec<UserRoleBindingNode>>> {
        let request = request_context(ctx)?;
        let binding_oids = self
            .binding_oids
            .iter()
            .copied()
            .take(MAX_PAYLOAD_BINDINGS)
            .collect();
        let records = integration::find_user_role_bindings(request, binding_oids)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(
            records.into_iter().map(UserRoleBindingNode::new).collect(),
        ))
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct AssignUserRolesInput {
    pub user_id: ID,
    #[graphql(validator(max_items = 100))]
    pub role_ids: Vec<ID>,
    pub expected_user_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct RevokeUserRolesInput {
    pub user_id: ID,
    #[graphql(validator(max_items = 100))]
    pub role_ids: Vec<ID>,
    pub expected_user_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) fn decode_user_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<UserOid> {
    decode_oid::<UserGlobalId>(ctx, id).map(UserOid)
}
