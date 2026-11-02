//! Transactional persistence port for instance administrator management.
//!
//! Implementations must re-verify the issuing client policy, actor binding,
//! authorization snapshot and target owner state inside the same transaction
//! that mutates the binding. Target CAS, generation advancement and the semantic
//! audit fact commit together. No SQL, SeaORM or HTTP type crosses this
//! boundary.

use std::{error::Error as StdError, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::{
    authorization::{
        AdministratorBinding, AdministratorBindingOid, AdministratorRole, AuthorizationVersion,
        GrantReason,
    },
    user::UserOid,
};

use crate::authorization::ManagementAuthorizationError;

use super::model::{AdministratorFilter, AdministratorManagementAuthority, AdministratorOrder};

/// One stable keyset sort key. Administrator order is always created-at plus the
/// unique binding row id as a deterministic tie-breaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdministratorSortKey {
    CreatedAt { created_at: DateTime<Utc>, id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministratorPageDirection {
    Forward,
    Backward,
}

/// Normalized query consumed by the repository. Filters are already trimmed and
/// length-checked; the cursor fingerprint is verified by the service.
#[derive(Debug, Clone)]
pub struct AdministratorQuery {
    pub filter: AdministratorFilter,
    pub order: AdministratorOrder,
    pub direction: AdministratorPageDirection,
    pub after: Option<AdministratorSortKey>,
    pub before: Option<AdministratorSortKey>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct AdministratorPageEntry {
    pub sort_key: AdministratorSortKey,
    pub binding: AdministratorBinding,
}

#[derive(Debug, Clone)]
pub struct AdministratorPageData {
    pub items: Vec<AdministratorPageEntry>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Clone)]
pub struct AssignAdministratorTransaction {
    pub user_oid: UserOid,
    pub role: AdministratorRole,
    pub reason: GrantReason,
    pub authority: AdministratorManagementAuthority,
}

#[derive(Clone)]
pub struct UpdateAdministratorRoleTransaction {
    pub binding_oid: AdministratorBindingOid,
    pub role: AdministratorRole,
    pub expected_version: AuthorizationVersion,
    pub reason: GrantReason,
    pub authority: AdministratorManagementAuthority,
}

#[derive(Clone)]
pub struct RevokeAdministratorTransaction {
    pub binding_oid: AdministratorBindingOid,
    pub expected_version: AuthorizationVersion,
    pub reason: GrantReason,
    pub authority: AdministratorManagementAuthority,
}

#[derive(Debug, thiserror::Error)]
pub enum AdministratorManagementRepositoryError {
    #[error("administrator management storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("administrator management authorization recheck failed")]
    Authorization(#[source] ManagementAuthorizationError),
    #[error("administrator management audit commit failed")]
    AuditFailed(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("persisted administrator binding is malformed")]
    CorruptRecord,
    #[error("user not found")]
    UserNotFound,
    #[error("administrator binding not found")]
    AdministratorNotFound,
    #[error("user already has an active administrator binding")]
    AlreadyAssigned,
    #[error("administrator binding is already revoked")]
    AlreadyRevoked,
    #[error("optimistic version conflict; current version is {current_version}")]
    VersionConflict {
        current_version: AuthorizationVersion,
    },
    #[error("last recoverable owner is protected")]
    LastOwnerProtected,
    #[error("administrator account is not allowed to manage administrators")]
    AccountInactive,
}

#[async_trait]
pub trait AdministratorManagementRepository: Send + Sync {
    async fn find_administrator(
        &self,
        oid: AdministratorBindingOid,
    ) -> Result<Option<AdministratorBinding>, AdministratorManagementRepositoryError>;

    async fn list_administrators(
        &self,
        query: AdministratorQuery,
    ) -> Result<AdministratorPageData, AdministratorManagementRepositoryError>;

    async fn assign_administrator(
        &self,
        command: AssignAdministratorTransaction,
    ) -> Result<AdministratorBinding, AdministratorManagementRepositoryError>;

    async fn update_administrator_role(
        &self,
        command: UpdateAdministratorRoleTransaction,
    ) -> Result<AdministratorBinding, AdministratorManagementRepositoryError>;

    async fn revoke_administrator(
        &self,
        command: RevokeAdministratorTransaction,
    ) -> Result<AdministratorBinding, AdministratorManagementRepositoryError>;
}

/// Convenience alias used by the composition root and adapters.
pub type SharedAdministratorManagementRepository = Arc<dyn AdministratorManagementRepository>;
