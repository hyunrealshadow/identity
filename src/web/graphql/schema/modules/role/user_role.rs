use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, Guard, GuardExt, ID, InputObject, Object, Result as GraphqlResult,
    connection::{Edge, EmptyFields},
};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        EffectiveGroupPermissionSourceRecord,
        EffectivePermissionOrder as RbacEffectivePermissionOrder, EffectivePermissionRecord,
        EffectivePermissionSourceRecord, RoleUserPageRequest, ScopeOid, UserRoleMutationResult,
        UserRoleOrder as RbacUserRoleOrder, UserRolePage, UserRolePageRequest, UserRoleRecord,
    },
};
use identity_domain::{
    authorization::ManagementScope, openid_connect::ApiScope, rbac::RoleOid, user::UserOid,
};
use identity_infrastructure::graphql::id::GlobalId;
use uuid::Uuid;

use super::{
    super::{
        account::{UserGlobalId, UserNode},
        group::{integration as group_integration, types as group_types, types::GroupNode},
        resource::support::{PageArgs, RbacConnectionCursor, decode_oid},
        resource::types as resource_types,
        role::{integration, types::RoleNode},
        scope::types as scope_types,
    },
    types,
};
use crate::graphql::schema::{
    RequestContext,
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::app_error,
    management_guard::ManagementGuard,
    modules::{
        relation::{
            RelationConnection, RelationFacts, RoleUserConnectionName, RoleUserEdgeName,
            UserRoleConnectionName, UserRoleEdgeName, UserVersionFields, index_by,
        },
        user::integration as user_integration,
    },
};

/// `User.roles`: role nodes with the user's assignment facts on each edge.
pub(crate) type UserRoleConnection =
    RelationConnection<RoleNode, UserVersionFields, UserRoleConnectionName, UserRoleEdgeName>;

/// `Role.users`: user nodes with the role assignment facts on each edge.
pub(crate) type RoleUserConnection =
    RelationConnection<UserNode, EmptyFields, RoleUserConnectionName, RoleUserEdgeName>;

fn user_global_id(oid: UserOid) -> ID {
    GlobalId::<UserGlobalId>::new(oid.0).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum UserRoleOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
}

impl UserRoleOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<UserRoleOrder> for RbacUserRoleOrder {
    fn from(order: UserRoleOrder) -> Self {
        match order {
            UserRoleOrder::CreatedAtAsc => Self::CreatedAtAsc,
            UserRoleOrder::CreatedAtDesc => Self::CreatedAtDesc,
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

fn facts(record: &UserRoleRecord) -> RelationFacts {
    RelationFacts {
        granted_by_user_oid: record.granted_by_user_oid,
        reason: record.reason.clone(),
        enabled: record.enabled,
        revoked_at: record.revoked_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

/// One page of a user's role assignments, with each role loaded in a single
/// batch.
pub(crate) async fn load_user_roles(
    ctx: &Context<'_>,
    request: &RequestContext,
    user_oid: UserOid,
    enabled: Option<bool>,
    order: UserRoleOrder,
    page: PageArgs,
) -> GraphqlResult<UserRoleConnection> {
    let page = integration::list_user_roles(
        request,
        UserRolePageRequest {
            user_oid,
            enabled,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        },
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let user_version = match page.user_version {
        Some(version) => version,
        None => current_user_version(ctx, request, user_oid).await?,
    };
    let roles = integration::find_roles(
        request,
        page.items.iter().map(|item| item.record.role_oid).collect(),
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let mut roles = index_by(roles, |role| role.oid.0);
    let mut connection = UserRoleConnection::with_additional_fields(
        page.has_previous_page,
        page.has_next_page,
        UserVersionFields { user_version },
    );
    for item in page.items {
        if let Some(role) = roles.remove(&item.record.role_oid.0) {
            connection.edges.push(Edge::with_additional_fields(
                RbacConnectionCursor::from_backend(item.cursor),
                RoleNode::new(role),
                facts(&item.record),
            ));
        }
    }
    Ok(connection)
}

/// `list_user_roles` always reports the single user's version; this only
/// guards against an adapter that omits it.
async fn current_user_version(
    ctx: &Context<'_>,
    request: &RequestContext,
    user_oid: UserOid,
) -> GraphqlResult<Uuid> {
    user_integration::find_user(request, user_oid)
        .await
        .map_err(|error| app_error(ctx, error))?
        .map(|user| user.version)
        .ok_or_else(|| "user not found".into())
}

/// One page of a role's user assignments, with each user loaded in a single
/// batch.
pub(crate) async fn load_role_users(
    ctx: &Context<'_>,
    request: &RequestContext,
    role_oid: RoleOid,
    enabled: Option<bool>,
    order: UserRoleOrder,
    page: PageArgs,
) -> GraphqlResult<RoleUserConnection> {
    let page: UserRolePage = integration::list_role_users(
        request,
        RoleUserPageRequest {
            role_oid,
            enabled,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        },
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let users = user_integration::find_users(
        request,
        page.items.iter().map(|item| item.record.user_oid).collect(),
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let mut users = index_by(users, |user| user.oid.0);
    let mut connection = RoleUserConnection::new(page.has_previous_page, page.has_next_page);
    for item in page.items {
        if let Some(user) = users.remove(&item.record.user_oid.0) {
            connection.edges.push(Edge::with_additional_fields(
                RbacConnectionCursor::from_backend(item.cursor),
                UserNode::managed(user),
                facts(&item.record),
            ));
        }
    }
    Ok(connection)
}

pub(crate) struct EffectivePermissionSourceNode {
    record: EffectivePermissionSourceRecord,
}

impl From<EffectivePermissionSourceRecord> for EffectivePermissionSourceNode {
    fn from(record: EffectivePermissionSourceRecord) -> Self {
        Self { record }
    }
}

/// A role assigned directly to the user that grants the permission.
#[Object(name = "EffectivePermissionSource")]
impl EffectivePermissionSourceNode {
    #[graphql(complexity = 0)]
    async fn role_id(&self) -> ID {
        types::role_global_id(self.record.role_oid)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead))
    )]
    async fn role(&self, ctx: &Context<'_>) -> GraphqlResult<Option<RoleNode>> {
        find_role(ctx, self.record.role_oid).await
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

/// A role granted through one of the user's active groups.
#[Object(name = "EffectiveGroupPermissionSource")]
impl EffectiveGroupPermissionSourceNode {
    #[graphql(complexity = 0)]
    async fn group_id(&self) -> ID {
        group_types::group_global_id(self.record.group_oid)
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

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead))
    )]
    async fn role(&self, ctx: &Context<'_>) -> GraphqlResult<Option<RoleNode>> {
        find_role(ctx, self.record.role_oid).await
    }
}

async fn find_role(ctx: &Context<'_>, oid: RoleOid) -> GraphqlResult<Option<RoleNode>> {
    let record = integration::find_role(request_context(ctx)?, oid)
        .await
        .map_err(|error| app_error(ctx, error))?;
    Ok(record.map(RoleNode::new))
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

    #[graphql(complexity = "child_complexity")]
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

/// Result of assigning or revoking a user's roles.
pub(crate) struct UserRolesPayload {
    user_oid: UserOid,
    user_version: Uuid,
    created_count: i32,
    revoked_count: i32,
    client_mutation_id: Option<String>,
}

impl UserRolesPayload {
    pub(crate) fn new(result: UserRoleMutationResult, client_mutation_id: Option<String>) -> Self {
        Self {
            user_oid: result.user_oid,
            user_version: result.user_version,
            created_count: i32::try_from(result.created_count).unwrap_or(i32::MAX),
            revoked_count: i32::try_from(result.revoked_count).unwrap_or(i32::MAX),
            client_mutation_id,
        }
    }
}

#[Object]
impl UserRolesPayload {
    async fn user_id(&self) -> ID {
        user_global_id(self.user_oid)
    }

    async fn user_version(&self) -> Uuid {
        self.user_version
    }

    async fn created_count(&self) -> i32 {
        self.created_count
    }

    async fn revoked_count(&self) -> i32 {
        self.revoked_count
    }

    /// The changed user, for refetching `roles`. Scalar payload fields stay
    /// unguarded so a writer without read authority can still confirm the
    /// write.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn user(&self, ctx: &Context<'_>) -> GraphqlResult<Option<UserNode>> {
        let user = user_integration::find_user(request_context(ctx)?, self.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(user.map(UserNode::managed))
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
