use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, Guard, GuardExt, ID, InputObject, Object, Result as GraphqlResult,
    connection::{Edge, EmptyFields},
};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        AuthorizationSource as RbacAuthorizationSource, EffectiveGroupPermissionSourceRecord,
        EffectivePermissionOrder as RbacEffectivePermissionOrder, EffectivePermissionRecord,
        EffectivePermissionSourceRecord, RoleUserPageRequest, ScopeOid, UserRoleGrant,
        UserRoleMutationResult, UserRoleOrder as RbacUserRoleOrder, UserRolePage,
        UserRolePageRequest, UserRoleRecord,
    },
};
use identity_domain::global_id::GlobalId;
use identity_domain::{
    authorization::ManagementScope,
    openid_connect::ApiScope,
    rbac::{GroupOid, RoleOid},
    user::UserOid,
};
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

/// `User.roles`: role nodes with the source of each role on its edge.
pub(crate) type UserRoleConnection = async_graphql::connection::Connection<
    RbacConnectionCursor,
    RoleNode,
    UserVersionFields,
    UserRoleFacts,
    UserRoleConnectionName,
    UserRoleEdgeName,
>;

/// `Role.users`: user nodes with the role assignment facts on each edge.
pub(crate) type RoleUserConnection =
    RelationConnection<UserNode, EmptyFields, RoleUserConnectionName, RoleUserEdgeName>;

fn user_global_id(oid: UserOid) -> ID {
    ID(GlobalId::<UserGlobalId>::new(oid.0).encode())
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

/// Where a user's role or permission comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum AuthorizationSource {
    /// Assigned to the user directly.
    #[graphql(name = "DIRECT")]
    Direct,
    /// Inherited through an active membership in an enabled group.
    #[graphql(name = "GROUP")]
    Group,
}

impl From<AuthorizationSource> for RbacAuthorizationSource {
    fn from(source: AuthorizationSource) -> Self {
        match source {
            AuthorizationSource::Direct => Self::Direct,
            AuthorizationSource::Group => Self::Group,
        }
    }
}

/// Listing or filtering by group-derived access reveals memberships and group
/// roles, so it needs both of those read scopes in addition to the field's own
/// declaration.
pub(crate) async fn ensure_group_source_read(ctx: &Context<'_>) -> GraphqlResult<()> {
    ManagementGuard::new(
        ManagementScope::GroupMembershipsRead,
        ManagementTarget::instance(),
    )
    .check(ctx)
    .await?;
    ManagementGuard::new(
        ManagementScope::GroupRolesRead,
        ManagementTarget::instance(),
    )
    .check(ctx)
    .await
}

/// Edge facts of `User.roles`. Direct rows carry the assignment facts;
/// inherited rows are live grants through `group`.
pub(crate) struct UserRoleFacts {
    facts: RelationFacts,
    source: AuthorizationSource,
    group_oid: Option<GroupOid>,
}

#[Object]
impl UserRoleFacts {
    /// Whether the role was assigned directly or inherited through a group.
    #[graphql(complexity = 0)]
    async fn source(&self) -> AuthorizationSource {
        self.source
    }

    /// Whether the relation is active. Revoked relations remain as history;
    /// inherited roles are always active.
    #[graphql(complexity = 0)]
    async fn enabled(&self) -> bool {
        self.facts.enabled
    }

    #[graphql(complexity = 0)]
    async fn revoked_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.facts.revoked_at
    }

    #[graphql(complexity = 0)]
    async fn reason(&self) -> &str {
        &self.facts.reason
    }

    /// When the user obtained the role. For an inherited role this is the
    /// later of joining the group and the group receiving the role.
    #[graphql(complexity = 0)]
    async fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.facts.created_at
    }

    #[graphql(complexity = 0)]
    async fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.facts.updated_at
    }

    /// The user who assigned a direct role, when one was recorded and still
    /// exists.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn granted_by(&self, ctx: &Context<'_>) -> GraphqlResult<Option<UserNode>> {
        let Some(user_oid) = self.facts.granted_by_user_oid else {
            return Ok(None);
        };
        let user = user_integration::find_user(request_context(ctx)?, user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(user.map(UserNode::managed))
    }

    /// The group an inherited role comes from.
    #[graphql(complexity = 0)]
    async fn group_id(&self) -> Option<ID> {
        self.group_oid.map(group_types::group_global_id)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead))
    )]
    async fn group(&self, ctx: &Context<'_>) -> GraphqlResult<Option<GroupNode>> {
        let Some(group_oid) = self.group_oid else {
            return Ok(None);
        };
        let record = group_integration::find_group(request_context(ctx)?, group_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(GroupNode::new))
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

/// One page of a user's roles, with each role loaded in a single batch.
pub(crate) async fn load_user_roles(
    ctx: &Context<'_>,
    request: &RequestContext,
    user_oid: UserOid,
    source: Option<AuthorizationSource>,
    enabled: Option<bool>,
    order: UserRoleOrder,
    page: PageArgs,
) -> GraphqlResult<UserRoleConnection> {
    if source != Some(AuthorizationSource::Direct) {
        ensure_group_source_read(ctx).await?;
    }
    let page = integration::list_user_roles(
        request,
        UserRolePageRequest {
            user_oid,
            source: source.map(Into::into),
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
    let roles = integration::find_roles(
        request,
        page.items
            .iter()
            .map(|item| item.grant.role_oid())
            .collect(),
    )
    .await
    .map_err(|error| app_error(ctx, error))?;
    let roles = index_by(roles, |role| role.oid.0);
    let mut connection = UserRoleConnection::with_additional_fields(
        page.has_previous_page,
        page.has_next_page,
        UserVersionFields {
            user_version: page.user_version,
        },
    );
    for item in page.items {
        let Some(role) = roles.get(&item.grant.role_oid().0) else {
            continue;
        };
        let fields = match &item.grant {
            UserRoleGrant::Direct(record) => UserRoleFacts {
                facts: facts(record),
                source: AuthorizationSource::Direct,
                group_oid: None,
            },
            UserRoleGrant::Group(record) => UserRoleFacts {
                facts: RelationFacts {
                    granted_by_user_oid: None,
                    reason: String::new(),
                    enabled: true,
                    revoked_at: None,
                    created_at: record.created_at,
                    updated_at: None,
                },
                source: AuthorizationSource::Group,
                group_oid: Some(record.group_oid),
            },
        };
        connection.edges.push(Edge::with_additional_fields(
            RbacConnectionCursor::from_backend(item.cursor),
            RoleNode::new(role.clone()),
            fields,
        ));
    }
    Ok(connection)
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
