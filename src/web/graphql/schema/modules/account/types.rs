use crate::graphql::schema::access::access;
use async_graphql::{Context, ID, InputObject, MaybeUndefined, Object, Result as GraphqlResult};
use chrono::{DateTime, Utc};
use identity_domain::user::{User, UserTheme, repository::UserProfilePatch};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::super::user::access::ensure_user_management_read;
use crate::graphql::schema::{authorization::request_context, management_guard::ManagementGuard};
use identity_application::authorization::ManagementTarget;
use identity_domain::authorization::ManagementScope;

pub(crate) struct UserGlobalId;

impl GlobalIdType for UserGlobalId {
    const TYPE_NAME: &'static str = "User";
}

pub(crate) struct UserNode {
    id: ID,
    user: User,
    /// One authoritative `management.user.read` decision per node. Selecting
    /// several management metadata fields therefore does not reload the live
    /// authority for every field. A newly returned node (for example after a
    /// mutation) gets a fresh cell and is re-authorized.
    management_read: OnceCell<()>,
}

pub(crate) fn user_global_id(user: &User) -> ID {
    GlobalId::<UserGlobalId>::new(Uuid::from(user.oid)).into()
}

impl From<User> for UserNode {
    fn from(user: User) -> Self {
        let id = user_global_id(&user);
        Self {
            id,
            user,
            management_read: OnceCell::new(),
        }
    }
}

impl UserNode {
    /// Management reads expose the core user UUID version. Fields still require
    /// `management.user.read` when selected.
    pub(crate) fn managed(user: User) -> Self {
        let id = user_global_id(&user);
        Self {
            id,
            user,
            management_read: OnceCell::new(),
        }
    }

    pub(crate) fn oid(&self) -> identity_domain::user::UserOid {
        self.user.oid
    }

    async fn ensure_management_metadata(&self, ctx: &Context<'_>) -> GraphqlResult<()> {
        self.management_read
            .get_or_try_init(|| async { ensure_user_management_read(ctx, self.user.oid).await })
            .await
            .map(|_| ())
    }
}

#[Object(name = "User")]
impl UserNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::GroupMembershipsRead, ManagementTarget::instance()))",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead)),
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupMembershipsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn groups(
        &self,
        ctx: &Context<'_>,
        filter: Option<super::super::group::types::GroupFilter>,
        order_by: Option<super::super::group::types::GroupOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<
        async_graphql::connection::Connection<
            super::super::resource::support::RbacConnectionCursor,
            super::super::group::types::GroupNode,
            crate::graphql::schema::connection::ConnectionTotal,
        >,
    > {
        let mut filter = filter.unwrap_or_default();
        filter.user_id = Some(self.id.clone());
        let page = super::super::resource::support::page_args(ctx, first, after, last, before)?;
        super::super::group::query::load_group_connection(
            ctx,
            request_context(ctx)?,
            filter,
            order_by.unwrap_or_else(super::super::group::types::GroupOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    async fn role_bindings(
        &self,
        ctx: &Context<'_>,
        enabled: Option<bool>,
        order_by: Option<super::super::role::binding::UserRoleBindingOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<
        async_graphql::connection::Connection<
            super::super::resource::support::RbacConnectionCursor,
            super::super::role::binding::UserRoleBindingNode,
            super::super::role::binding::UserRoleBindingConnectionFields,
        >,
    > {
        let page = super::super::resource::support::page_args(ctx, first, after, last, before)?;
        super::super::role::query::load_binding_connection(
            ctx,
            request_context(ctx)?,
            super::super::role::query::BindingTarget::User(self.oid()),
            enabled,
            order_by
                .unwrap_or_else(super::super::role::binding::UserRoleBindingOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * (1 + child_complexity)"
    )]
    async fn effective_permissions(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
        order_by: Option<super::super::role::binding::EffectivePermissionOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<super::super::role::connection::EffectivePermissionConnection> {
        let page = super::super::resource::support::page_args(ctx, first, after, last, before)?;
        let resource = super::super::role::query::decode_resource_oid(ctx, &resource_id)?;
        super::super::role::query::load_effective_permission_connection(
            ctx,
            request_context(ctx)?,
            self.oid(),
            resource,
            order_by.unwrap_or_else(
                super::super::role::binding::EffectivePermissionOrder::default_order,
            ),
            page,
        )
        .await
    }

    async fn username(&self) -> &str {
        &self.user.name
    }

    async fn email(&self) -> &str {
        &self.user.email
    }

    async fn email_verified(&self) -> bool {
        self.user.email_verified
    }

    async fn given_name(&self) -> Option<&str> {
        self.user.given_name.as_deref()
    }

    async fn family_name(&self) -> Option<&str> {
        self.user.family_name.as_deref()
    }

    async fn middle_name(&self) -> Option<&str> {
        self.user.middle_name.as_deref()
    }

    async fn nickname(&self) -> Option<&str> {
        self.user.nickname.as_deref()
    }

    async fn profile(&self) -> Option<&str> {
        self.user.profile.as_deref()
    }

    async fn picture(&self) -> Option<&str> {
        self.user.picture.as_deref()
    }

    async fn website(&self) -> Option<&str> {
        self.user.website.as_deref()
    }

    async fn birthdate(&self) -> Option<&str> {
        self.user.birthdate.as_deref()
    }

    #[graphql(name = "zoneInfo")]
    async fn zone_info(&self) -> Option<&str> {
        self.user.zoneinfo.as_deref()
    }

    async fn locale(&self) -> Option<&str> {
        self.user.locale.as_deref()
    }

    async fn theme(&self) -> Option<&str> {
        self.user.theme.map(UserTheme::as_str)
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.user.created_at
    }

    async fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.user.updated_at
    }

    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn version(&self, ctx: &Context<'_>) -> GraphqlResult<Uuid> {
        self.ensure_management_metadata(ctx).await?;
        Ok(self.user.version)
    }

    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn enabled(&self, ctx: &Context<'_>) -> GraphqlResult<Option<bool>> {
        self.ensure_management_metadata(ctx).await?;
        Ok(Some(self.user.enabled))
    }

    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn locked(&self, ctx: &Context<'_>) -> GraphqlResult<Option<bool>> {
        self.ensure_management_metadata(ctx).await?;
        Ok(Some(self.user.locked))
    }

    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn locked_until(&self, ctx: &Context<'_>) -> GraphqlResult<Option<DateTime<Utc>>> {
        self.ensure_management_metadata(ctx).await?;
        Ok(self.user.locked_until)
    }

    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn failed_attempts(&self, ctx: &Context<'_>) -> GraphqlResult<Option<i32>> {
        self.ensure_management_metadata(ctx).await?;
        Ok(Some(self.user.failed_attempts))
    }
}

#[derive(Clone, InputObject)]
pub(super) struct UpdateProfileInput {
    #[graphql(validator(chars_max_length = 255))]
    pub given_name: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub family_name: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub middle_name: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub nickname: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub profile: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub picture: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub website: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub gender: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 64))]
    pub birthdate: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub zone_info: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 35))]
    pub locale: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 16))]
    pub theme: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_formatted: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_street_address: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_locality: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_region: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 32))]
    pub address_postal_code: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_country: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

impl UpdateProfileInput {
    /// Theme is the only semantic value rule in this patch. It is validated in
    /// the resolver so the failure is localized; the returned error type keeps
    /// the raw English out of the input adapter.
    pub(super) fn into_patch(self) -> std::result::Result<UserProfilePatch, ()> {
        let theme = patch_value(self.theme)
            .map(|value| value.map(|theme| theme.parse()).transpose().map_err(|_| ()))
            .transpose()?;
        Ok(UserProfilePatch {
            given_name: patch_value(self.given_name),
            family_name: patch_value(self.family_name),
            middle_name: patch_value(self.middle_name),
            nickname: patch_value(self.nickname),
            profile: patch_value(self.profile),
            picture: patch_value(self.picture),
            website: patch_value(self.website),
            gender: patch_value(self.gender),
            birthdate: patch_value(self.birthdate),
            zone_info: patch_value(self.zone_info),
            locale: patch_value(self.locale),
            theme,
            preferred_mfa_method: None,
            address_formatted: patch_value(self.address_formatted),
            address_street_address: patch_value(self.address_street_address),
            address_locality: patch_value(self.address_locality),
            address_region: patch_value(self.address_region),
            address_postal_code: patch_value(self.address_postal_code),
            address_country: patch_value(self.address_country),
        })
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateUsernameInput {
    #[graphql(validator(chars_min_length = 3, chars_max_length = 64))]
    pub username: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateEmailInput {
    #[graphql(validator(chars_max_length = 320))]
    pub email: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(super) struct UpdateProfilePayload {
    user: UserNode,
    client_mutation_id: Option<String>,
}

impl UpdateProfilePayload {
    pub(super) fn new(user: UserNode, client_mutation_id: Option<String>) -> Self {
        Self {
            user,
            client_mutation_id,
        }
    }
}

#[Object]
impl UpdateProfilePayload {
    async fn user(&self) -> &UserNode {
        &self.user
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

fn patch_value(value: MaybeUndefined<String>) -> Option<Option<String>> {
    match value {
        MaybeUndefined::Undefined => None,
        MaybeUndefined::Null => Some(None),
        MaybeUndefined::Value(value) => Some(Some(value.trim().to_string())),
    }
}
