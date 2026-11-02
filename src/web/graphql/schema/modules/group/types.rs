use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result as GraphqlResult, connection::Connection,
};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    rbac::{
        GroupMembershipMutationResult, GroupMembershipRecord, GroupRecord, GroupRoleBindingRecord,
        GroupRoleMutationResult,
    },
};
use identity_domain::{
    authorization::ManagementScope,
    rbac::{GroupMembershipOid, GroupOid, GroupRoleBindingOid, LocalizedText, RoleOid},
    user::UserOid,
};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

use super::super::{
    account::{UserGlobalId, UserNode},
    resource::support::{RbacConnectionCursor, decode_oid, decode_oids, page_args},
    role::{
        integration as role_integration,
        types::{RoleNode, decode_role_oid as decode_role_oid_from_id},
    },
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
    modules::user::integration as user_integration,
};

use super::query;

pub(crate) struct GroupGlobalId;

impl GlobalIdType for GroupGlobalId {
    const TYPE_NAME: &'static str = "Group";
}

pub(crate) struct GroupMembershipGlobalId;

impl GlobalIdType for GroupMembershipGlobalId {
    const TYPE_NAME: &'static str = "GroupMembership";
}

pub(crate) struct GroupRoleBindingGlobalId;

impl GlobalIdType for GroupRoleBindingGlobalId {
    const TYPE_NAME: &'static str = "GroupRoleBinding";
}

pub(crate) fn group_global_id(oid: GroupOid) -> ID {
    GlobalId::<GroupGlobalId>::new(oid.0).into()
}

pub(crate) fn group_user_global_id(oid: UserOid) -> ID {
    GlobalId::<UserGlobalId>::new(oid.0).into()
}

pub(crate) fn membership_global_id(oid: GroupMembershipOid) -> ID {
    GlobalId::<GroupMembershipGlobalId>::new(oid.0).into()
}

pub(crate) fn group_role_global_id(oid: GroupRoleBindingOid) -> ID {
    GlobalId::<GroupRoleBindingGlobalId>::new(oid.0).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum GroupOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
}

impl GroupOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<GroupOrder> for identity_application::rbac::GroupOrder {
    fn from(order: GroupOrder) -> Self {
        match order {
            GroupOrder::CreatedAtAsc => Self::CreatedAtAsc,
            GroupOrder::CreatedAtDesc => Self::CreatedAtDesc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum GroupMembershipOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
}

impl GroupMembershipOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<GroupMembershipOrder> for identity_application::rbac::GroupMembershipOrder {
    fn from(order: GroupMembershipOrder) -> Self {
        match order {
            GroupMembershipOrder::CreatedAtAsc => Self::CreatedAtAsc,
            GroupMembershipOrder::CreatedAtDesc => Self::CreatedAtDesc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum GroupRoleOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
    #[graphql(name = "ROLE_NAME_ASC")]
    RoleNameAsc,
    #[graphql(name = "ROLE_NAME_DESC")]
    RoleNameDesc,
}

impl GroupRoleOrder {
    pub(crate) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

impl From<GroupRoleOrder> for identity_application::rbac::GroupRoleOrder {
    fn from(order: GroupRoleOrder) -> Self {
        match order {
            GroupRoleOrder::CreatedAtAsc => Self::CreatedAtAsc,
            GroupRoleOrder::CreatedAtDesc => Self::CreatedAtDesc,
            GroupRoleOrder::RoleNameAsc => Self::RoleNameAsc,
            GroupRoleOrder::RoleNameDesc => Self::RoleNameDesc,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct GroupFilter {
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
    pub enabled: Option<bool>,
    pub built_in: Option<bool>,
    pub user_id: Option<ID>,
    pub role_id: Option<ID>,
}

impl GroupFilter {
    pub(crate) fn into_application(
        self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<identity_application::rbac::GroupFilter> {
        let user_oid = self
            .user_id
            .as_ref()
            .map(|id| decode_oid::<UserGlobalId>(ctx, id))
            .transpose()?
            .map(UserOid);
        let role_oid = self
            .role_id
            .as_ref()
            .map(|id| decode_role_oid_from_id(ctx, id))
            .transpose()?;
        Ok(identity_application::rbac::GroupFilter {
            query: self.query,
            enabled: self.enabled,
            built_in: self.built_in,
            user_oid,
            role_oid,
        })
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct LocalizedTextInput {
    #[graphql(validator(chars_min_length = 1, chars_max_length = 35))]
    pub locale: String,
    #[graphql(validator(chars_max_length = 1024))]
    pub value: String,
}

impl From<LocalizedTextInput> for LocalizedText {
    fn from(input: LocalizedTextInput) -> Self {
        Self {
            locale: input.locale,
            value: input.value,
        }
    }
}

pub(crate) struct LocalizedTextNode {
    locale: String,
    value: String,
}

impl From<LocalizedText> for LocalizedTextNode {
    fn from(value: LocalizedText) -> Self {
        Self {
            locale: value.locale,
            value: value.value,
        }
    }
}

#[Object(name = "LocalizedText")]
impl LocalizedTextNode {
    async fn locale(&self) -> &str {
        &self.locale
    }

    async fn value(&self) -> &str {
        &self.value
    }
}

pub(crate) struct GroupNode {
    id: ID,
    record: GroupRecord,
}

impl GroupNode {
    pub(crate) fn new(record: GroupRecord) -> Self {
        Self {
            id: group_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "Group")]
impl GroupNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    async fn name(&self) -> &str {
        &self.record.name
    }

    async fn description(&self) -> &str {
        &self.record.description
    }

    async fn built_in(&self) -> bool {
        self.record.built_in
    }

    async fn names(&self) -> Vec<LocalizedTextNode> {
        self.record
            .names
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
    }

    async fn descriptions(&self) -> Vec<LocalizedTextNode> {
        self.record
            .descriptions
            .iter()
            .cloned()
            .map(LocalizedTextNode::from)
            .collect()
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
        guard = "ManagementGuard::new(ManagementScope::GroupMembershipsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupMembershipsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn members(
        &self,
        ctx: &Context<'_>,
        filter: Option<GroupMembershipFilter>,
        order_by: Option<GroupMembershipOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<Connection<RbacConnectionCursor, GroupMembershipNode>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        query::load_membership_connection(
            ctx,
            request,
            self.record.oid,
            filter.unwrap_or_default(),
            order_by.unwrap_or_else(GroupMembershipOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupRolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupRolesRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn roles(
        &self,
        ctx: &Context<'_>,
        filter: Option<GroupRoleFilter>,
        order_by: Option<GroupRoleOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<Connection<RbacConnectionCursor, GroupRoleBindingNode>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        query::load_group_role_connection(
            ctx,
            request,
            self.record.oid,
            filter.unwrap_or_default(),
            order_by.unwrap_or_else(GroupRoleOrder::default_order),
            page,
        )
        .await
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct GroupMembershipFilter {
    pub enabled: Option<bool>,
    pub user_id: Option<ID>,
}

impl GroupMembershipFilter {
    pub(crate) fn into_application(
        self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<identity_application::rbac::GroupMembershipFilter> {
        let user_oid = self
            .user_id
            .as_ref()
            .map(|id| decode_oid::<UserGlobalId>(ctx, id))
            .transpose()?
            .map(UserOid);
        Ok(identity_application::rbac::GroupMembershipFilter {
            enabled: self.enabled,
            user_oid,
        })
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct GroupRoleFilter {
    pub enabled: Option<bool>,
    pub role_id: Option<ID>,
}

impl GroupRoleFilter {
    pub(crate) fn into_application(
        self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<identity_application::rbac::GroupRoleFilter> {
        let role_oid = self
            .role_id
            .as_ref()
            .map(|id| decode_role_oid_from_id(ctx, id))
            .transpose()?;
        Ok(identity_application::rbac::GroupRoleFilter {
            enabled: self.enabled,
            role_oid,
        })
    }
}

pub(crate) struct GroupMembershipNode {
    id: ID,
    record: GroupMembershipRecord,
}

impl GroupMembershipNode {
    pub(crate) fn new(record: GroupMembershipRecord) -> Self {
        Self {
            id: membership_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "GroupMembership")]
impl GroupMembershipNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    async fn group_id(&self) -> ID {
        group_global_id(self.record.group_oid)
    }

    async fn user_id(&self) -> ID {
        group_user_global_id(self.record.user_oid)
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

    async fn granted_by_user_id(&self) -> Option<ID> {
        self.record.granted_by_user_oid.map(group_user_global_id)
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

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }
}

pub(crate) struct GroupRoleBindingNode {
    id: ID,
    record: GroupRoleBindingRecord,
}

impl GroupRoleBindingNode {
    pub(crate) fn new(record: GroupRoleBindingRecord) -> Self {
        Self {
            id: group_role_global_id(record.oid),
            record,
        }
    }
}

#[Object(name = "GroupRoleBinding")]
impl GroupRoleBindingNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    async fn group_id(&self) -> ID {
        group_global_id(self.record.group_oid)
    }

    async fn role_id(&self) -> ID {
        super::super::role::types::role_global_id(self.record.role_oid)
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead))
    )]
    async fn role(&self, ctx: &Context<'_>) -> GraphqlResult<Option<RoleNode>> {
        let request = request_context(ctx)?;
        let record = role_integration::find_role(request, self.record.role_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(RoleNode::new))
    }

    async fn granted_by_user_id(&self) -> Option<ID> {
        self.record.granted_by_user_oid.map(group_user_global_id)
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

    async fn created_at(&self) -> DateTime<Utc> {
        self.record.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.record.updated_at
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateGroupInput {
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
pub(crate) struct UpdateGroupInput {
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
pub(crate) struct GroupStateInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct SetGroupEnabledInput {
    pub id: ID,
    pub enabled: bool,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct AddGroupMemberInput {
    pub group_id: ID,
    pub user_id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct RemoveGroupMemberInput {
    pub group_id: ID,
    pub user_id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct SetGroupRolesInput {
    pub group_id: ID,
    #[graphql(validator(max_items = 1000))]
    pub role_ids: Vec<ID>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct GroupPayload {
    group_id: ID,
    version: Uuid,
    client_mutation_id: Option<String>,
}

impl GroupPayload {
    pub(crate) fn new(record: GroupRecord, client_mutation_id: Option<String>) -> Self {
        Self {
            group_id: group_global_id(record.oid),
            version: record.version,
            client_mutation_id,
        }
    }
}

#[Object]
impl GroupPayload {
    async fn group_id(&self) -> &ID {
        &self.group_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) struct DeleteGroupPayload {
    group_id: ID,
    deleted: bool,
    client_mutation_id: Option<String>,
}

impl DeleteGroupPayload {
    pub(crate) fn new(
        group_oid: GroupOid,
        deleted: bool,
        client_mutation_id: Option<String>,
    ) -> Self {
        Self {
            group_id: group_global_id(group_oid),
            deleted,
            client_mutation_id,
        }
    }
}

#[Object]
impl DeleteGroupPayload {
    async fn group_id(&self) -> &ID {
        &self.group_id
    }

    async fn deleted(&self) -> bool {
        self.deleted
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) struct GroupMemberPayload {
    group_id: ID,
    user_id: ID,
    membership_id: ID,
    group_version: Uuid,
    membership_version: Uuid,
    client_mutation_id: Option<String>,
}

impl GroupMemberPayload {
    pub(crate) fn new(
        result: GroupMembershipMutationResult,
        client_mutation_id: Option<String>,
    ) -> Self {
        Self {
            group_id: group_global_id(result.group_oid),
            user_id: group_user_global_id(result.membership.user_oid),
            membership_id: membership_global_id(result.membership.oid),
            group_version: result.group_version,
            membership_version: result.membership.version,
            client_mutation_id,
        }
    }
}

#[Object]
impl GroupMemberPayload {
    async fn group_id(&self) -> &ID {
        &self.group_id
    }

    async fn user_id(&self) -> &ID {
        &self.user_id
    }

    async fn membership_id(&self) -> &ID {
        &self.membership_id
    }

    async fn group_version(&self) -> Uuid {
        self.group_version
    }

    async fn membership_version(&self) -> Uuid {
        self.membership_version
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) struct GroupRolesPayload {
    group_id: ID,
    group_version: Uuid,
    role_ids: Vec<ID>,
    added_count: i32,
    removed_count: i32,
    client_mutation_id: Option<String>,
}

impl GroupRolesPayload {
    pub(crate) fn new(result: GroupRoleMutationResult, client_mutation_id: Option<String>) -> Self {
        Self {
            group_id: group_global_id(result.group_oid),
            group_version: result.group_version,
            role_ids: result
                .role_oids
                .into_iter()
                .map(super::super::role::types::role_global_id)
                .collect(),
            added_count: i32::try_from(result.added_count).unwrap_or(i32::MAX),
            removed_count: i32::try_from(result.removed_count).unwrap_or(i32::MAX),
            client_mutation_id,
        }
    }
}

#[Object]
impl GroupRolesPayload {
    async fn group_id(&self) -> &ID {
        &self.group_id
    }

    async fn group_version(&self) -> Uuid {
        self.group_version
    }

    async fn role_ids(&self) -> &[ID] {
        &self.role_ids
    }

    async fn added_count(&self) -> i32 {
        self.added_count
    }

    async fn removed_count(&self) -> i32 {
        self.removed_count
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) fn decode_group_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<GroupOid> {
    decode_oid::<GroupGlobalId>(ctx, id).map(GroupOid)
}

pub(crate) fn decode_group_membership_oid(
    ctx: &Context<'_>,
    id: &ID,
) -> GraphqlResult<GroupMembershipOid> {
    decode_oid::<GroupMembershipGlobalId>(ctx, id).map(GroupMembershipOid)
}

pub(crate) fn decode_group_role_oid(
    ctx: &Context<'_>,
    id: &ID,
) -> GraphqlResult<GroupRoleBindingOid> {
    decode_oid::<GroupRoleBindingGlobalId>(ctx, id).map(GroupRoleBindingOid)
}

pub(crate) fn decode_user_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<UserOid> {
    decode_oid::<UserGlobalId>(ctx, id).map(UserOid)
}

pub(crate) fn decode_role_oids(ctx: &Context<'_>, ids: &[ID]) -> GraphqlResult<Vec<RoleOid>> {
    decode_oids::<super::super::role::types::RoleGlobalId>(ctx, ids)
        .map(|ids| ids.into_iter().map(RoleOid).collect())
}
