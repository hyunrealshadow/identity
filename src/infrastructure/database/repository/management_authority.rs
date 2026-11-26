//! Shared transactional row-locking checks for management authority.

use identity_application::authorization::ManagementAuthorizationError;
use identity_domain::{
    authorization::{PolicyVersion, authority::UserPermissionAuthority},
    user::UserOid,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, Statement};
use uuid::Uuid;

use super::authorization::load_user_permission_authority;
use crate::database::client_authorization_boundary;

pub(crate) enum ManagementAuthorityCheckError {
    Storage(DbErr),
    Authorization(ManagementAuthorizationError),
}

/// Lock the issuing client row and re-derive its live authorization boundary.
///
/// The credential carries the original boundary fingerprint. A missing client,
/// a changed live boundary, or a stale fingerprint fails closed. Display text,
/// metadata and the client's UUID CAS version never participate.
pub(crate) async fn lock_and_recheck_issuing_client(
    txn: &DatabaseTransaction,
    client_oid: Uuid,
    client_policy_version: PolicyVersion,
) -> Result<(), ManagementAuthorityCheckError> {
    let client_row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM client WHERE oid = $1 FOR UPDATE",
            [client_oid.into()],
        ))
        .await
        .map_err(ManagementAuthorityCheckError::Storage)?;
    let Some(client_row) = client_row else {
        return Err(ManagementAuthorityCheckError::Authorization(
            ManagementAuthorizationError::NoCurrentGrant,
        ));
    };
    let client_id = client_row
        .try_get::<i64>("", "id")
        .map_err(ManagementAuthorityCheckError::Storage)?;
    let (_, fingerprint) =
        client_authorization_boundary::client_boundary_fingerprint(txn, client_id)
            .await
            .map_err(ManagementAuthorityCheckError::Storage)?;
    if fingerprint != client_policy_version {
        return Err(ManagementAuthorityCheckError::Authorization(
            ManagementAuthorizationError::SnapshotPolicyMismatch,
        ));
    }
    Ok(())
}

/// Lock the authoritative actor user row `FOR UPDATE` before reading its live
/// management permissions in the same transaction.
pub(crate) async fn lock_and_load_user_authority(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
) -> Result<Option<UserPermissionAuthority>, DbErr> {
    let user_row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM \"user\" WHERE oid = $1 FOR UPDATE",
            [Uuid::from(user_oid).into()],
        ))
        .await?;
    if user_row.is_none() {
        return Ok(None);
    }
    load_user_permission_authority(txn, user_oid).await
}
