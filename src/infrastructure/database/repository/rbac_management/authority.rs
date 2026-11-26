//! Transaction-scoped authoritative management authority recheck.

use chrono::Utc;
use identity_application::{
    authorization::{
        CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError,
        ManagementAuthorizationRequest, ManagementTarget, evaluate_management_authority,
    },
    rbac::{RbacManagementAuthority, RbacManagementRepositoryError},
};
use identity_domain::{
    authorization::{ActorPrincipal, ManagementScope, policy_fingerprint},
    user::UserOid,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::support::storage;
use crate::database::repository::{
    authorization,
    authorization::load_user_permission_authority,
    authorization_lifecycle,
    management_authority::{
        ManagementAuthorityCheckError, lock_and_load_user_authority,
        lock_and_recheck_issuing_client,
    },
};

pub(crate) async fn user_id_by_oid<C: ConnectionTrait>(
    db: &C,
    oid: UserOid,
) -> Result<Option<i64>, RbacManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM \"user\" WHERE oid = $1",
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?;
    match row {
        Some(row) => row.try_get::<i64>("", "id").map(Some).map_err(storage),
        None => Ok(None),
    }
}

pub(crate) async fn load_current_authority(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
) -> Result<Option<CurrentManagementAuthority>, RbacManagementRepositoryError> {
    match &authority.actor.principal {
        ActorPrincipal::User { user_oid, .. } => {
            let authority = lock_and_load_user_authority(txn, *user_oid)
                .await
                .map_err(|error| RbacManagementRepositoryError::Storage(Box::new(error)))?;
            Ok(authority.map(CurrentManagementAuthority::UserPermissions))
        }
        ActorPrincipal::Client { client_oid } => {
            let authority = authorization::load_client_scope_authority(txn, *client_oid)
                .await
                .map_err(storage)?;
            Ok(authority.map(CurrentManagementAuthority::ClientScopes))
        }
    }
}

/// The target holds the complete trusted management capability set.
///
/// This replaces the retired "is Owner" check; it never inspects role keys,
/// display names or built-in group membership.
pub(crate) async fn target_is_owner(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
) -> Result<bool, RbacManagementRepositoryError> {
    let authority = load_user_permission_authority(txn, user_oid)
        .await
        .map_err(|error| RbacManagementRepositoryError::Storage(Box::new(error)))?;
    Ok(authority.is_some_and(|authority| authority.has_full_management_permissions()))
}

fn map_authority_check(error: ManagementAuthorityCheckError) -> RbacManagementRepositoryError {
    match error {
        ManagementAuthorityCheckError::Storage(error) => storage(error),
        ManagementAuthorityCheckError::Authorization(error) => {
            RbacManagementRepositoryError::Authorization(error)
        }
    }
}

/// Re-verify entry authority with authoritative rows in the write transaction.
pub(crate) async fn recheck_authority(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    required: ManagementScope,
    target_user: Option<UserOid>,
) -> Result<CurrentManagementAuthority, RbacManagementRepositoryError> {
    authorization_lifecycle::lock_owner_lifecycle(txn)
        .await
        .map_err(storage)?;
    lock_and_recheck_issuing_client(txn, authority.client_oid, authority.client_policy_version)
        .await
        .map_err(map_authority_check)?;
    let current = load_current_authority(txn, authority).await?;
    let policy_version = policy_fingerprint();
    let target = if let Some(user_oid) = target_user {
        ManagementTarget::user(user_oid, target_is_owner(txn, user_oid).await?)
    } else {
        ManagementTarget::instance()
    };
    evaluate_management_authority(&ManagementAuthorizationRequest {
        actor: &authority.actor,
        token_scopes: &authority.token_scopes,
        required,
        target,
        current_authority: current.as_ref(),
        snapshot: authority.snapshot.as_ref(),
        credential_client_boundary: Some(authority.client_policy_version),
        current_policy_version: policy_version,
        now: Utc::now(),
        recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
    })
    .map_err(RbacManagementRepositoryError::Authorization)?;
    current.ok_or(RbacManagementRepositoryError::Authorization(
        ManagementAuthorizationError::NoCurrentGrant,
    ))
}
