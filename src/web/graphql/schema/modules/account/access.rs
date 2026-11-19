//! Self-service group, role, and effective-permission projections for the
//! authenticated account (`user.read` only).

use std::collections::{BTreeSet, HashMap};

use async_graphql::{
    Context, ID, Object, Result,
    connection::{CursorType, PageInfo},
};
use chrono::{DateTime, Utc};
use identity_application::{
    error::AppError,
    rbac::{
        AccountGroupPageRequest, AccountPermissionPageRequest, AccountPermissionRecord,
        AccountRoleGrant, AccountRolePageRequest, GroupRecord, RoleRecord, ScopeOid,
    },
};
use identity_domain::rbac::{GroupOid, ResourceOid, RoleOid};

use super::super::{
    group::{
        integration as group_integration,
        types::{GroupOrder, LocalizedTextNode, group_global_id},
    },
    relation::index_by,
    resource::{
        support::{PageArgs, RbacConnectionCursor, decode_oid},
        types::{ResourceGlobalId, resource_global_id},
    },
    role::{
        integration as role_integration,
        types::role_global_id,
        user_role::{AuthorizationSource, EffectivePermissionOrder, UserRoleOrder},
    },
    scope::types::scope_global_id,
};
use crate::graphql::schema::{
    RequestContext,
    connection::{self, ConnectionTotal},
    error::app_error,
};

const BATCH_LOOKUP_CHUNK: usize = 100;

#[derive(Clone)]
pub(crate) struct AccountGroupNode {
    id: ID,
    record: GroupRecord,
}

impl From<GroupRecord> for AccountGroupNode {
    fn from(record: GroupRecord) -> Self {
        Self {
            id: group_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "AccountGroup")]
impl AccountGroupNode {
    #[graphql(complexity = 0)]
    async fn id(&self) -> &ID {
        &self.id
    }

    #[graphql(complexity = 0)]
    async fn name(&self) -> &str {
        &self.record.name
    }

    #[graphql(complexity = 0)]
    async fn description(&self) -> &str {
        &self.record.description
    }

    #[graphql(complexity = 0)]
    async fn names(&self) -> Vec<LocalizedTextNode> {
        self.record
            .names
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn descriptions(&self) -> Vec<LocalizedTextNode> {
        self.record
            .descriptions
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn built_in(&self) -> bool {
        self.record.built_in
    }
}

pub(crate) struct AccountGroupEdge {
    cursor: RbacConnectionCursor,
    joined_at: DateTime<Utc>,
    node: AccountGroupNode,
}

#[Object]
impl AccountGroupEdge {
    #[graphql(complexity = 0)]
    async fn cursor(&self) -> String {
        self.cursor.encode_cursor()
    }

    #[graphql(complexity = 0)]
    async fn joined_at(&self) -> DateTime<Utc> {
        self.joined_at
    }

    #[graphql(complexity = "child_complexity")]
    async fn node(&self) -> &AccountGroupNode {
        &self.node
    }
}

pub(crate) struct AccountGroupConnection {
    edges: Vec<AccountGroupEdge>,
    has_previous_page: bool,
    has_next_page: bool,
    total_count: u64,
}

#[Object]
impl AccountGroupConnection {
    #[graphql(complexity = 0)]
    async fn page_info(&self) -> PageInfo {
        PageInfo {
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.edges.first().map(|edge| edge.cursor.encode_cursor()),
            end_cursor: self.edges.last().map(|edge| edge.cursor.encode_cursor()),
        }
    }

    #[graphql(complexity = "child_complexity")]
    async fn edges(&self) -> &[AccountGroupEdge] {
        &self.edges
    }

    #[graphql(complexity = "child_complexity")]
    async fn nodes(&self) -> Vec<&AccountGroupNode> {
        self.edges.iter().map(|edge| &edge.node).collect()
    }

    #[graphql(complexity = 0)]
    async fn total_count(&self) -> u64 {
        self.total_count
    }
}

#[derive(Clone)]
pub(crate) struct AccountRoleNode {
    id: ID,
    record: RoleRecord,
}

impl From<RoleRecord> for AccountRoleNode {
    fn from(record: RoleRecord) -> Self {
        Self {
            id: role_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "AccountRole")]
impl AccountRoleNode {
    #[graphql(complexity = 0)]
    async fn id(&self) -> &ID {
        &self.id
    }

    #[graphql(complexity = 0)]
    async fn name(&self) -> &str {
        &self.record.name
    }

    #[graphql(complexity = 0)]
    async fn description(&self) -> &str {
        &self.record.description
    }

    #[graphql(complexity = 0)]
    async fn names(&self) -> Vec<LocalizedTextNode> {
        self.record
            .names
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn descriptions(&self) -> Vec<LocalizedTextNode> {
        self.record
            .descriptions
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn built_in(&self) -> bool {
        self.record.built_in
    }
}

pub(crate) struct AccountRoleEdge {
    cursor: RbacConnectionCursor,
    source: AuthorizationSource,
    granted_at: DateTime<Utc>,
    group_id: Option<ID>,
    group: Option<AccountGroupNode>,
    node: AccountRoleNode,
}

#[Object]
impl AccountRoleEdge {
    #[graphql(complexity = 0)]
    async fn cursor(&self) -> String {
        self.cursor.encode_cursor()
    }

    #[graphql(complexity = 0)]
    async fn source(&self) -> AuthorizationSource {
        self.source
    }

    #[graphql(complexity = 0)]
    async fn granted_at(&self) -> DateTime<Utc> {
        self.granted_at
    }

    #[graphql(complexity = 0)]
    async fn group_id(&self) -> Option<&ID> {
        self.group_id.as_ref()
    }

    #[graphql(complexity = "child_complexity")]
    async fn group(&self) -> Option<&AccountGroupNode> {
        self.group.as_ref()
    }

    #[graphql(complexity = "child_complexity")]
    async fn node(&self) -> &AccountRoleNode {
        &self.node
    }
}

pub(crate) struct AccountRoleConnection {
    edges: Vec<AccountRoleEdge>,
    has_previous_page: bool,
    has_next_page: bool,
    total_count: u64,
}

#[Object]
impl AccountRoleConnection {
    #[graphql(complexity = 0)]
    async fn page_info(&self) -> PageInfo {
        PageInfo {
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.edges.first().map(|edge| edge.cursor.encode_cursor()),
            end_cursor: self.edges.last().map(|edge| edge.cursor.encode_cursor()),
        }
    }

    #[graphql(complexity = "child_complexity")]
    async fn edges(&self) -> &[AccountRoleEdge] {
        &self.edges
    }

    #[graphql(complexity = "child_complexity")]
    async fn nodes(&self) -> Vec<&AccountRoleNode> {
        self.edges.iter().map(|edge| &edge.node).collect()
    }

    #[graphql(complexity = 0)]
    async fn total_count(&self) -> u64 {
        self.total_count
    }
}

pub(crate) struct AccountPermissionRoleSource {
    role_id: ID,
    role: AccountRoleNode,
}

#[Object]
impl AccountPermissionRoleSource {
    #[graphql(complexity = 0)]
    async fn role_id(&self) -> &ID {
        &self.role_id
    }

    #[graphql(complexity = "child_complexity")]
    async fn role(&self) -> &AccountRoleNode {
        &self.role
    }
}

pub(crate) struct AccountPermissionGroupSource {
    group_id: ID,
    role_id: ID,
    group: AccountGroupNode,
    role: AccountRoleNode,
}

#[Object]
impl AccountPermissionGroupSource {
    #[graphql(complexity = 0)]
    async fn group_id(&self) -> &ID {
        &self.group_id
    }

    #[graphql(complexity = 0)]
    async fn role_id(&self) -> &ID {
        &self.role_id
    }

    #[graphql(complexity = "child_complexity")]
    async fn group(&self) -> &AccountGroupNode {
        &self.group
    }

    #[graphql(complexity = "child_complexity")]
    async fn role(&self) -> &AccountRoleNode {
        &self.role
    }
}

pub(crate) struct AccountPermissionNode {
    permission_id: ID,
    resource_id: ID,
    record: AccountPermissionRecord,
    sources: Vec<AccountPermissionRoleSource>,
    group_sources: Vec<AccountPermissionGroupSource>,
}

#[Object(name = "AccountPermission")]
impl AccountPermissionNode {
    #[graphql(complexity = 0)]
    async fn permission_id(&self) -> &ID {
        &self.permission_id
    }

    #[graphql(complexity = 0)]
    async fn resource_id(&self) -> &ID {
        &self.resource_id
    }

    #[graphql(complexity = 0)]
    async fn resource_uri(&self) -> &str {
        &self.record.resource_uri
    }

    #[graphql(complexity = 0)]
    async fn resource_name(&self) -> &str {
        &self.record.resource_name
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
    async fn name(&self) -> &str {
        &self.record.name
    }

    #[graphql(complexity = 0)]
    async fn names(&self) -> Vec<LocalizedTextNode> {
        self.record
            .names
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn description(&self) -> &str {
        &self.record.description
    }

    #[graphql(complexity = 0)]
    async fn descriptions(&self) -> Vec<LocalizedTextNode> {
        self.record
            .descriptions
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn built_in(&self) -> bool {
        self.record.built_in
    }

    #[graphql(complexity = "child_complexity")]
    async fn sources(&self) -> &[AccountPermissionRoleSource] {
        &self.sources
    }

    #[graphql(complexity = "child_complexity")]
    async fn group_sources(&self) -> &[AccountPermissionGroupSource] {
        &self.group_sources
    }
}

pub(crate) struct AccountPermissionEdge {
    cursor: RbacConnectionCursor,
    node: AccountPermissionNode,
}

#[Object]
impl AccountPermissionEdge {
    #[graphql(complexity = 0)]
    async fn cursor(&self) -> String {
        self.cursor.encode_cursor()
    }

    #[graphql(complexity = "child_complexity")]
    async fn node(&self) -> &AccountPermissionNode {
        &self.node
    }
}

pub(crate) struct AccountPermissionConnection {
    edges: Vec<AccountPermissionEdge>,
    has_previous_page: bool,
    has_next_page: bool,
    total_count: u64,
}

#[Object]
impl AccountPermissionConnection {
    #[graphql(complexity = 0)]
    async fn page_info(&self) -> PageInfo {
        PageInfo {
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.edges.first().map(|edge| edge.cursor.encode_cursor()),
            end_cursor: self.edges.last().map(|edge| edge.cursor.encode_cursor()),
        }
    }

    #[graphql(complexity = "child_complexity")]
    async fn edges(&self) -> &[AccountPermissionEdge] {
        &self.edges
    }

    #[graphql(complexity = "child_complexity")]
    async fn nodes(&self) -> Vec<&AccountPermissionNode> {
        self.edges.iter().map(|edge| &edge.node).collect()
    }

    #[graphql(complexity = 0)]
    async fn total_count(&self) -> u64 {
        self.total_count
    }
}

async fn batch_find_roles(
    request: &RequestContext,
    oids: impl IntoIterator<Item = RoleOid>,
) -> std::result::Result<HashMap<RoleOid, RoleRecord>, AppError> {
    let unique = oids.into_iter().collect::<BTreeSet<_>>();
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    let unique = unique.into_iter().collect::<Vec<_>>();
    let mut all = Vec::with_capacity(unique.len());
    for chunk in unique.chunks(BATCH_LOOKUP_CHUNK) {
        let found = role_integration::find_roles(request, chunk.to_vec()).await?;
        all.extend(found);
    }
    Ok(index_by(all, |role| role.oid))
}

async fn batch_find_groups(
    request: &RequestContext,
    oids: impl IntoIterator<Item = GroupOid>,
) -> std::result::Result<HashMap<GroupOid, GroupRecord>, AppError> {
    let unique = oids.into_iter().collect::<BTreeSet<_>>();
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    let unique = unique.into_iter().collect::<Vec<_>>();
    let mut all = Vec::with_capacity(unique.len());
    for chunk in unique.chunks(BATCH_LOOKUP_CHUNK) {
        let found = group_integration::find_groups(request, chunk.to_vec()).await?;
        all.extend(found);
    }
    Ok(index_by(all, |group| group.oid))
}

pub(crate) async fn load_account_groups(
    ctx: &Context<'_>,
    request: &RequestContext,
    order: GroupOrder,
    page: PageArgs,
) -> Result<AccountGroupConnection> {
    let user_oid = request.user_oid()?;
    let page_result = request
        .state
        .services()
        .group_management()
        .list_account_groups(AccountGroupPageRequest {
            user_oid,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
        .map_err(|error| app_error(ctx, error))?;
    let total: ConnectionTotal = connection::connection_total(ctx, async {
        request
            .state
            .services()
            .group_management()
            .count_account_groups(user_oid)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;

    let edges = page_result
        .items
        .into_iter()
        .map(|item| AccountGroupEdge {
            cursor: RbacConnectionCursor::from_backend(item.cursor),
            joined_at: item.record.joined_at,
            node: AccountGroupNode::from(item.record.group),
        })
        .collect();
    Ok(AccountGroupConnection {
        edges,
        has_previous_page: page_result.has_previous_page,
        has_next_page: page_result.has_next_page,
        total_count: total.total_count,
    })
}

pub(crate) async fn load_account_roles(
    ctx: &Context<'_>,
    request: &RequestContext,
    source: Option<AuthorizationSource>,
    order: UserRoleOrder,
    page: PageArgs,
) -> Result<AccountRoleConnection> {
    let user_oid = request.user_oid()?;
    let app_source = source.map(Into::into);
    let page_result = request
        .state
        .services()
        .rbac_management()
        .list_account_roles(AccountRolePageRequest {
            user_oid,
            source: app_source,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
        .map_err(|error| app_error(ctx, error))?;
    let total = connection::connection_total(ctx, async {
        request
            .state
            .services()
            .rbac_management()
            .count_account_roles(user_oid, app_source)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;

    let role_oids = page_result
        .items
        .iter()
        .map(|item| item.grant.role_oid())
        .collect::<Vec<_>>();
    let group_oids = page_result
        .items
        .iter()
        .filter_map(|item| item.grant.group_oid())
        .collect::<Vec<_>>();
    let roles = batch_find_roles(request, role_oids)
        .await
        .map_err(|error| app_error(ctx, error))?;
    let groups = batch_find_groups(request, group_oids)
        .await
        .map_err(|error| app_error(ctx, error))?;

    let mut edges = Vec::with_capacity(page_result.items.len());
    for item in page_result.items {
        let Some(role) = roles.get(&item.grant.role_oid()) else {
            continue;
        };
        let (edge_source, group_id, group, granted_at) = match item.grant {
            AccountRoleGrant::Direct { granted_at, .. } => {
                (AuthorizationSource::Direct, None, None, granted_at)
            }
            AccountRoleGrant::Group {
                group_oid,
                granted_at,
                ..
            } => {
                let Some(group) = groups.get(&group_oid) else {
                    continue;
                };
                (
                    AuthorizationSource::Group,
                    Some(group_global_id(group_oid)),
                    Some(AccountGroupNode::from(group.clone())),
                    granted_at,
                )
            }
        };
        edges.push(AccountRoleEdge {
            cursor: RbacConnectionCursor::from_backend(item.cursor),
            source: edge_source,
            granted_at,
            group_id,
            group,
            node: AccountRoleNode::from(role.clone()),
        });
    }

    Ok(AccountRoleConnection {
        edges,
        has_previous_page: page_result.has_previous_page,
        has_next_page: page_result.has_next_page,
        total_count: total.total_count,
    })
}

pub(crate) async fn load_account_permissions(
    ctx: &Context<'_>,
    request: &RequestContext,
    resource_id: Option<ID>,
    source: Option<AuthorizationSource>,
    order: EffectivePermissionOrder,
    page: PageArgs,
) -> Result<AccountPermissionConnection> {
    let user_oid = request.user_oid()?;
    let resource_oid = resource_id
        .as_ref()
        .map(|id| decode_oid::<ResourceGlobalId>(ctx, id).map(ResourceOid))
        .transpose()?;
    let app_source = source.map(Into::into);
    let page_result = request
        .state
        .services()
        .rbac_management()
        .list_account_permissions(AccountPermissionPageRequest {
            user_oid,
            resource_oid,
            source: app_source,
            order: order.into(),
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
        .map_err(|error| app_error(ctx, error))?;
    let total = connection::connection_total(ctx, async {
        request
            .state
            .services()
            .rbac_management()
            .count_account_permissions(user_oid, resource_oid, app_source)
            .await
            .map_err(|error| app_error(ctx, error))
    })
    .await?;

    let role_oids = page_result
        .items
        .iter()
        .flat_map(|item| {
            item.record
                .sources
                .iter()
                .map(|source| source.role_oid)
                .chain(
                    item.record
                        .group_sources
                        .iter()
                        .map(|source| source.role_oid),
                )
        })
        .collect::<Vec<_>>();
    let group_oids = page_result
        .items
        .iter()
        .flat_map(|item| {
            item.record
                .group_sources
                .iter()
                .map(|source| source.group_oid)
        })
        .collect::<Vec<_>>();
    let roles = batch_find_roles(request, role_oids)
        .await
        .map_err(|error| app_error(ctx, error))?;
    let groups = batch_find_groups(request, group_oids)
        .await
        .map_err(|error| app_error(ctx, error))?;

    let mut edges = Vec::with_capacity(page_result.items.len());
    for item in page_result.items {
        let record = item.record;
        let sources = record
            .sources
            .iter()
            .filter_map(|source| {
                let role = roles.get(&source.role_oid)?;
                Some(AccountPermissionRoleSource {
                    role_id: role_global_id(source.role_oid),
                    role: AccountRoleNode::from(role.clone()),
                })
            })
            .collect();
        let group_sources = record
            .group_sources
            .iter()
            .filter_map(|source| {
                let group = groups.get(&source.group_oid)?;
                let role = roles.get(&source.role_oid)?;
                Some(AccountPermissionGroupSource {
                    group_id: group_global_id(source.group_oid),
                    role_id: role_global_id(source.role_oid),
                    group: AccountGroupNode::from(group.clone()),
                    role: AccountRoleNode::from(role.clone()),
                })
            })
            .collect();
        edges.push(AccountPermissionEdge {
            cursor: RbacConnectionCursor::from_backend(item.cursor),
            node: AccountPermissionNode {
                permission_id: scope_global_id(ScopeOid(record.permission_oid.0)),
                resource_id: resource_global_id(record.resource_oid),
                record,
                sources,
                group_sources,
            },
        });
    }

    Ok(AccountPermissionConnection {
        edges,
        has_previous_page: page_result.has_previous_page,
        has_next_page: page_result.has_next_page,
        total_count: total.total_count,
    })
}
