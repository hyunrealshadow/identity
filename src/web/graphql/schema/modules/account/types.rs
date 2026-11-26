use std::result::Result as StdResult;

use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Enum, ID, InputObject, MaybeUndefined, Object, Result as GraphqlResult,
    connection::Connection,
};
use chrono::{DateTime, Utc};
use identity_domain::global_id::GlobalId;
use identity_domain::user::{RequiredAction, User, UserTheme, repository::UserProfilePatch};
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::super::{
    group::{
        query,
        types::{GroupFilter, GroupNode, GroupOrder},
    },
    role::{
        connection::EffectivePermissionConnection,
        query as role_query,
        user_role::{
            AuthorizationSource, EffectivePermissionOrder, UserRoleConnection, UserRoleOrder,
            load_user_roles,
        },
    },
    session::{SessionNode, session_connection},
    user::access::ensure_user_management_read,
};
use crate::graphql::schema::{
    authorization::request_context,
    connection::{self, ConnectionTotal, OpaqueCursor},
    management_guard::ManagementGuard,
};
use identity_application::authorization::ManagementTarget;
use identity_application::user::CredentialType;
use identity_domain::{authorization::ManagementScope, user::UserOid};

/// Something the user must do at their next sign-in before it completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "UserRequiredAction", remote = "RequiredAction")]
pub(crate) enum UserRequiredAction {
    /// Replace the password.
    ChangePassword,
}

pub(crate) use identity_domain::global_id::kind::User as UserGlobalId;

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
    ID(GlobalId::<UserGlobalId>::new(Uuid::from(user.oid)).encode())
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

    pub(crate) fn oid(&self) -> UserOid {
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
        guard = "ManagementGuard::new(ManagementScope::GroupsRead, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::GroupMembersRead, ManagementTarget::instance()))",
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupsRead)),
        directive = access::apply(ManagementGuard::policy(ManagementScope::GroupMembersRead)),
        complexity = "crate::graphql::schema::connection::page_complexity(first, last, child_complexity)"
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
    ) -> GraphqlResult<Connection<OpaqueCursor, GroupNode, ConnectionTotal>> {
        let mut filter = filter.unwrap_or_default();
        filter.user_id = Some(self.id.clone());
        let page = connection::page_args(ctx, first, after, last, before)?;
        query::load_group_connection(
            ctx,
            request_context(ctx)?,
            filter,
            order_by.unwrap_or_else(GroupOrder::default_order),
            page,
        )
        .await
    }

    /// The user's roles, assigned directly or inherited through groups, with
    /// the source on each edge. `source` narrows the list; leaving it unset or
    /// choosing `GROUP` also needs the group member and role assignment read
    /// scopes. Inherited roles are live grants and never appear as revoked.
    /// `userVersion` is the expected version for assigning or revoking.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::RolesRead, ManagementTarget::instance()))",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        directive = access::apply(ManagementGuard::policy(ManagementScope::RolesRead)),
        complexity = "crate::graphql::schema::connection::page_complexity(first, last, child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn roles(
        &self,
        ctx: &Context<'_>,
        source: Option<AuthorizationSource>,
        enabled: Option<bool>,
        order_by: Option<UserRoleOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<UserRoleConnection> {
        let page = connection::page_args(ctx, first, after, last, before)?;
        load_user_roles(
            ctx,
            request_context(ctx)?,
            self.oid(),
            source,
            enabled,
            order_by.unwrap_or_else(UserRoleOrder::default_order),
            page,
        )
        .await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::RoleAssignmentsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::RoleAssignmentsRead)),
        complexity = "crate::graphql::schema::connection::nested_page_complexity(first, last, child_complexity)"
    )]
    #[allow(clippy::too_many_arguments)]
    /// Permissions the user holds on one API resource. `source` keeps only
    /// permissions reachable through that source and needs the group
    /// member and role assignment read scopes.
    async fn effective_permissions(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
        source: Option<AuthorizationSource>,
        order_by: Option<EffectivePermissionOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> GraphqlResult<EffectivePermissionConnection> {
        let page = connection::page_args(ctx, first, after, last, before)?;
        let resource = role_query::decode_resource_oid(ctx, &resource_id)?;
        role_query::load_effective_permission_connection(
            ctx,
            request_context(ctx)?,
            self.oid(),
            resource,
            source,
            order_by.unwrap_or_else(EffectivePermissionOrder::default_order),
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

    async fn gender(&self) -> Option<&str> {
        self.user.gender.as_deref()
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

    async fn phone_number(&self) -> Option<&str> {
        self.user.phone_number.as_deref()
    }

    async fn phone_number_verified(&self) -> Option<bool> {
        self.user.phone_number_verified
    }

    async fn address_formatted(&self) -> Option<&str> {
        self.user.address_formatted.as_deref()
    }

    async fn address_street_address(&self) -> Option<&str> {
        self.user.address_street_address.as_deref()
    }

    async fn address_locality(&self) -> Option<&str> {
        self.user.address_locality.as_deref()
    }

    async fn address_region(&self) -> Option<&str> {
        self.user.address_region.as_deref()
    }

    async fn address_postal_code(&self) -> Option<&str> {
        self.user.address_postal_code.as_deref()
    }

    async fn address_country(&self) -> Option<&str> {
        self.user.address_country.as_deref()
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

    /// What the next sign-in must complete before a session is issued, as an
    /// administrator required. A password past its lifetime is not listed: the
    /// expiry is evaluated at sign-in.
    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn required_actions(
        &self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<Option<Vec<UserRequiredAction>>> {
        self.ensure_management_metadata(ctx).await?;
        Ok(Some(
            self.user
                .required_actions
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
        ))
    }

    /// The ways the user can sign in. Never the credentials themselves.
    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn authentication_methods(
        &self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<Option<UserAuthenticationMethods>> {
        self.ensure_management_metadata(ctx).await?;
        let request = request_context(ctx)?;
        let types = request
            .state
            .services()
            .login()
            .credential_types(self.user.oid)
            .await
            .map_err(|error| crate::graphql::schema::error::app_error(ctx, error))?;
        Ok(Some(UserAuthenticationMethods {
            password: types.contains(&CredentialType::Password),
            authenticator_app: types.contains(&CredentialType::Otp),
            recovery_codes: types.contains(&CredentialType::RecoveryCode),
            passkey: types.contains(&CredentialType::Passkey),
        }))
    }

    /// The invitation the user has not accepted yet: the account has no
    /// password and the link was sent to its current address.
    #[graphql(directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)))]
    async fn invitation(&self, ctx: &Context<'_>) -> GraphqlResult<Option<UserInvitation>> {
        self.ensure_management_metadata(ctx).await?;
        let request = request_context(ctx)?;
        let status = request
            .state
            .services()
            .user_management()
            .invitation_status(self.user.oid)
            .await
            .map_err(|error| crate::graphql::schema::error::app_error(ctx, error))?;
        Ok(status.map(Into::into))
    }

    /// The user's active sessions, most recently active first.
    #[graphql(
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)),
        complexity = "crate::graphql::schema::connection::page_complexity(first, last, child_complexity)"
    )]
    async fn sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
    ) -> GraphqlResult<Connection<OpaqueCursor, SessionNode>> {
        self.ensure_management_metadata(ctx).await?;
        session_connection(
            ctx,
            Uuid::from(self.user.oid),
            None,
            after,
            before,
            first,
            last,
        )
        .await
    }
}

/// An invitation to set a first password, as shown to administrators.
#[derive(async_graphql::SimpleObject)]
pub(crate) struct UserInvitation {
    pub sent_at: DateTime<Utc>,
    /// When the link stops working. Send the invitation again after that.
    pub expires_at: DateTime<Utc>,
    /// Where the latest invitation email stands.
    pub delivery: EmailDelivery,
}

impl From<identity_application::user::invitation::UserInvitationStatus> for UserInvitation {
    fn from(value: identity_application::user::invitation::UserInvitationStatus) -> Self {
        Self {
            sent_at: value.sent_at,
            expires_at: value.expires_at,
            delivery: value.delivery.into(),
        }
    }
}

/// Where a queued email stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(
    name = "EmailDeliveryStatus",
    remote = "identity_domain::email::EmailDeliveryStatus"
)]
pub(crate) enum EmailDeliveryStatus {
    /// Waiting for, or being tried by, the delivery worker.
    Queued,
    /// The mail server accepted it.
    Delivered,
    /// Given up; `failure` says why.
    Failed,
}

/// Why a queued email was given up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(
    name = "EmailDeliveryFailure",
    remote = "identity_domain::email::EmailDeliveryFailure"
)]
pub(crate) enum EmailDeliveryFailure {
    /// What it carried stopped working before it could be sent.
    Expired,
    /// Email delivery was turned off or is incomplete.
    NotConfigured,
    /// The mail server refused the address.
    InvalidAddress,
    /// The mail server refused the instance's credentials.
    AuthenticationFailed,
    /// The mail server refused the message for good, for example an
    /// unknown recipient.
    Rejected,
    /// The mail server could not be reached or kept failing.
    TransportFailed,
    /// The stored delivery secret could not be read.
    SecretUnavailable,
    /// The queued message could not be read back.
    MessageUnreadable,
}

/// The latest delivery outcome of an email.
#[derive(async_graphql::SimpleObject)]
pub(crate) struct EmailDelivery {
    pub status: EmailDeliveryStatus,
    /// Set when `status` is `FAILED`.
    pub failure: Option<EmailDeliveryFailure>,
    /// When the status was reached.
    pub updated_at: DateTime<Utc>,
}

impl From<identity_domain::email::EmailDeliveryReport> for EmailDelivery {
    fn from(value: identity_domain::email::EmailDeliveryReport) -> Self {
        Self {
            status: value.status.into(),
            failure: value.failure.map(Into::into),
            updated_at: value.at,
        }
    }
}

/// Which sign-in methods a user has set up.
#[derive(async_graphql::SimpleObject)]
pub(crate) struct UserAuthenticationMethods {
    pub password: bool,
    pub authenticator_app: bool,
    pub recovery_codes: bool,
    pub passkey: bool,
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
    pub(super) fn into_patch(self) -> StdResult<UserProfilePatch, ()> {
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
