//! Transactional port for user management persistence.
//!
//! Implementations must re-verify management authority inside the same
//! transaction that mutates the user, take row/advisory locks in the documented
//! order and write the semantic audit fact before commit. No SQL, SeaORM or
//! HTTP type crosses this boundary.

use std::error::Error as StdError;

use crate::{
    authorization::ManagementAuthorizationError,
    user::{
        Password,
        invitation::{InvitationIssue, UserInvitationStatus},
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::user::{
    RequiredActions, UserManagementRecord, UserOid, repository::UserProfilePatch,
};
use uuid::Uuid;

use super::model::{UserFilter, UserManagementAuthority, UserOrder};

/// Validated identifier pair. `value` preserves operator input; the normalized
/// value is authoritative for uniqueness and lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentifierValue {
    pub value: String,
    pub normalized: String,
}

/// One keyset sort key. The variant matches the requested [`UserOrder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserSortKey {
    CreatedAt { created_at: DateTime<Utc>, id: i64 },
    Username { name_normalized: String, id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPageDirection {
    Forward,
    Backward,
}

/// Normalized query consumed by the repository. Filters are already trimmed,
/// lower-cased and length-checked.
#[derive(Debug, Clone)]
pub struct UserManagementQuery {
    pub filter: UserFilter,
    pub order: UserOrder,
    pub direction: UserPageDirection,
    pub after: Option<UserSortKey>,
    pub before: Option<UserSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct UserManagementPageEntry {
    pub sort_key: UserSortKey,
    pub record: UserManagementRecord,
}

#[derive(Debug, Clone)]
pub struct UserManagementPageData {
    pub items: Vec<UserManagementPageEntry>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

/// Fully prepared create. The application service has already normalized
/// identifiers, validated the password and produced the stored hash. Exactly
/// one of `password` and `invitation` is set.
///
/// `Debug` is intentionally not derived because the stored credential hash must
/// never be logged.
#[derive(Clone)]
pub struct CreateUserTransaction {
    pub username: String,
    pub username_normalized: String,
    pub email: String,
    pub email_normalized: String,
    pub password: Option<Password>,
    pub invitation: Option<InvitationIssue>,
    pub profile: UserProfilePatch,
    pub reason: String,
    pub authority: UserManagementAuthority,
}

/// A new invitation link for a user who has no password yet. It replaces
/// any earlier link once `delivery` admits another email.
#[derive(Debug, Clone)]
pub struct SendUserInvitationTransaction {
    pub user_oid: UserOid,
    pub invitation: InvitationIssue,
    pub delivery: identity_domain::auth::challenge::DeliveryPolicy,
    pub reason: String,
    pub authority: UserManagementAuthority,
}

/// Business outcome of sending an invitation.
#[derive(Debug, Clone)]
pub enum UserInvitationOutcome {
    Sent {
        record: Box<UserManagementRecord>,
        invitation: UserInvitationStatus,
    },
    UserNotFound,
    /// The user already has a password.
    HasPassword,
    TooSoon {
        available_at: DateTime<Utc>,
    },
}

/// Fully prepared sparse update.
#[derive(Debug, Clone)]
pub struct UpdateUserTransaction {
    pub user_oid: UserOid,
    pub username: Option<UserIdentifierValue>,
    pub email: Option<UserIdentifierValue>,
    /// Mark the address verified or unverified. Without it, a changed
    /// address becomes unverified.
    pub email_verified: Option<bool>,
    /// Replace what the next sign-in must complete; `None` keeps it.
    pub required_actions: Option<RequiredActions>,
    pub profile: UserProfilePatch,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: UserManagementAuthority,
}

/// Fully prepared state mutation.
#[derive(Debug, Clone)]
pub struct UserStateTransaction {
    pub user_oid: UserOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub authority: UserManagementAuthority,
}

/// Sessions of one user to revoke: the listed ones, or all of them.
#[derive(Debug, Clone)]
pub struct RevokeUserSessionsTransaction {
    pub user_oid: UserOid,
    /// `None` revokes every active session.
    pub sessions: Option<Vec<Uuid>>,
    pub reason: String,
    pub authority: UserManagementAuthority,
}

/// Business outcomes that are not infrastructure errors.
#[derive(Debug, Clone)]
pub enum UserManagementMutationOutcome {
    Success(Box<UserManagementRecord>),
    UserNotFound,
    VersionConflict {
        current_version: Uuid,
    },
    LastOwnerProtected,
    UsernameExists,
    EmailExists,
    /// Only a disabled user may be deleted.
    NotDisabled,
    /// Second factors are cleared only while a password remains.
    NoPassword,
    /// A listed session is not an active session of the user.
    SessionNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum UserManagementRepositoryError {
    #[error("user management storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("user management authorization recheck failed")]
    Authorization(#[source] ManagementAuthorizationError),
    #[error("user management audit commit failed")]
    AuditFailed(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("persisted user management record is malformed")]
    CorruptRecord,
}

#[async_trait]
pub trait UserManagementRepository: Send + Sync {
    async fn count_users(&self, filter: UserFilter) -> Result<u64, UserManagementRepositoryError>;

    async fn list_users(
        &self,
        query: UserManagementQuery,
    ) -> Result<UserManagementPageData, UserManagementRepositoryError>;

    async fn find_user(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserManagementRecord>, UserManagementRepositoryError>;

    /// Users referenced by one page of relation edges. Unknown OIDs are
    /// omitted; callers bound the list to one page.
    async fn find_users(
        &self,
        user_oids: Vec<UserOid>,
    ) -> Result<Vec<UserManagementRecord>, UserManagementRepositoryError>;

    async fn create_user(
        &self,
        command: CreateUserTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    async fn update_user(
        &self,
        command: UpdateUserTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    async fn set_user_enabled(
        &self,
        command: UserStateTransaction,
        enabled: bool,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    async fn unlock_user(
        &self,
        command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    /// Replace (or add) the password with `password`, require a change at
    /// the next sign-in, end a lockout from failed attempts, and revoke every
    /// session with its grants. The replaced hash is kept for the history
    /// check while `keep_history` allows.
    async fn reset_user_password(
        &self,
        command: UserStateTransaction,
        password: Password,
        keep_history: u32,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    /// Remove the authenticator app, recovery codes and passkeys, and revoke
    /// every session with its grants. Refused while the user has no password.
    async fn reset_user_mfa(
        &self,
        command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    /// Revoke sessions of the user with the grants issued from them.
    async fn revoke_user_sessions(
        &self,
        command: RevokeUserSessionsTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;

    /// Store a new invitation link for a user without a password and audit
    /// it.
    async fn send_user_invitation(
        &self,
        command: SendUserInvitationTransaction,
    ) -> Result<UserInvitationOutcome, UserManagementRepositoryError>;

    /// Delete a disabled user with its credentials, sessions, consents and
    /// memberships. Grants it made to others keep their rows without it as
    /// granter; the audit log keeps the history.
    async fn delete_user(
        &self,
        command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError>;
}
