//! Foundation repository ports for management authorization.
//!
//! Application code depends on these ports. Infrastructure adapters own SQL and
//! transactions, map storage failures to [`ManagementRepositoryError`] and
//! return business outcomes (not SQL text) for missing/tombstoned/conflicting
//! records.

use std::error::Error as StdError;

use crate::{
    authorization::{
        authority::{ClientScopeAuthority, UserPermissionAuthority},
        ids::{AuthorizationVersion, PolicyVersion},
        snapshot::{ManagementAuthorizationSnapshot, ManagementGrantKind},
    },
    client::model::ClientOid,
    user::UserOid,
};

#[derive(Debug, thiserror::Error)]
pub enum ManagementRepositoryError {
    #[error("management authorization storage failure")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),
    #[error("persisted management authorization record is malformed")]
    CorruptRecord,
    #[error("authorization snapshot is stale, tombstoned, or no longer authoritative")]
    StaleSnapshot,
    #[error("authorization audit could not be appended")]
    AuditFailed(#[source] Box<dyn StdError + Send + Sync + 'static>),
}

/// Effective human management authority and its semantic dependency fingerprint.
#[async_trait::async_trait]
pub trait ManagementAuthorityRepository: Send + Sync {
    /// Effective whole-user management permission authority.
    ///
    /// Adapters must compute the union of active direct-role and group-role
    /// permissions and validate trusted built-in permission identities. There is
    /// no fallback to legacy administrator bindings.
    async fn find_user_permission_authority(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserPermissionAuthority>, ManagementRepositoryError>;

    async fn current_policy_version(&self) -> Result<PolicyVersion, ManagementRepositoryError>;

    /// Live machine management ceiling for one client and the first-party
    /// GraphQL resource. `None` means the client does not exist.
    async fn find_client_scope_authority(
        &self,
        client_oid: ClientOid,
    ) -> Result<Option<ClientScopeAuthority>, ManagementRepositoryError>;

    /// Validate an authorization snapshot against authoritative state. The
    /// default method keeps callers from comparing only role/scope names.
    async fn validate_snapshot(
        &self,
        snapshot: &ManagementAuthorizationSnapshot,
    ) -> Result<(), ManagementRepositoryError> {
        match snapshot.grant_kind {
            ManagementGrantKind::UserRbac => {
                let current = self
                    .find_user_permission_authority(UserOid(snapshot.grant_oid))
                    .await?;
                let policy = self.current_policy_version().await?;
                crate::authorization::snapshot::validate_user_permission_snapshot(
                    snapshot,
                    current.as_ref(),
                    policy,
                )
                .map_err(|_| ManagementRepositoryError::StaleSnapshot)
            }
            // The retired binding kind stays decodable but never validates.
            ManagementGrantKind::AdministratorBinding => {
                Err(ManagementRepositoryError::StaleSnapshot)
            }
        }
    }
}

/// Foundation result for scope/version mutation. The adapter must not expose
/// database error strings to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationVersionChange {
    pub user: UserOid,
    pub previous: AuthorizationVersion,
    pub current: AuthorizationVersion,
}

/// Return the stable snapshot identity fields only, for diagnostics.
#[must_use]
pub fn snapshot_identity(
    snapshot: &ManagementAuthorizationSnapshot,
) -> (uuid::Uuid, AuthorizationVersion, PolicyVersion) {
    (
        snapshot.grant_oid,
        snapshot.grant_fingerprint,
        snapshot.policy_version,
    )
}
