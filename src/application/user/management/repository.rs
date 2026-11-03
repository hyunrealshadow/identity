//! Transactional port for user management persistence.
//!
//! Implementations must re-verify management authority inside the same
//! transaction that mutates the user, take row/advisory locks in the documented
//! order and write the semantic audit fact before commit. No SQL, SeaORM or
//! HTTP type crosses this boundary.

use std::error::Error as StdError;

use crate::{authorization::ManagementAuthorizationError, user::Password};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::user::{UserManagementRecord, UserOid, repository::UserProfilePatch};
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
/// identifiers, validated the password and produced the stored hash.
///
/// `Debug` is intentionally not derived because the stored credential hash must
/// never be logged.
#[derive(Clone)]
pub struct CreateUserTransaction {
    pub username: String,
    pub username_normalized: String,
    pub email: String,
    pub email_normalized: String,
    pub password: Password,
    pub profile: UserProfilePatch,
    pub reason: String,
    pub authority: UserManagementAuthority,
}

/// Fully prepared sparse update.
#[derive(Debug, Clone)]
pub struct UpdateUserTransaction {
    pub user_oid: UserOid,
    pub username: Option<UserIdentifierValue>,
    pub email: Option<UserIdentifierValue>,
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

/// Business outcomes that are not infrastructure errors.
#[derive(Debug, Clone)]
pub enum UserManagementMutationOutcome {
    Success(Box<UserManagementRecord>),
    UserNotFound,
    VersionConflict { current_version: Uuid },
    LastOwnerProtected,
    UsernameExists,
    EmailExists,
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
}
