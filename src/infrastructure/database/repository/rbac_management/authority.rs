//! Transaction-scoped authoritative management authority recheck.

use chrono::Utc;
use identity_application::authorization::{
    CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError,
    ManagementAuthorizationRequest, ManagementTarget, evaluate_management_authority,
};
use identity_application::rbac::{RbacManagementAuthority, RbacManagementRepositoryError};
use identity_domain::{
    authorization::{ActorPrincipal, ManagementScope, policy_fingerprint},
    user::UserOid,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::support::storage;
use crate::database::repository::authorization::load_user_permission_authority;

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
            // Lock the authoritative user row before reading role/group paths.
            let Some(user_id) = user_id_by_oid(txn, *user_oid).await? else {
                return Ok(None);
            };
            let _ = txn
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT id FROM \"user\" WHERE id = $1 FOR UPDATE",
                    [user_id.into()],
                ))
                .await
                .map_err(storage)?;
            let authority = load_user_permission_authority(txn, *user_oid)
                .await
                .map_err(|error| RbacManagementRepositoryError::Storage(Box::new(error)))?;
            Ok(authority.map(CurrentManagementAuthority::UserPermissions))
        }
        ActorPrincipal::Client { client_oid } => {
            let authority =
                crate::database::repository::authorization::load_client_scope_authority(
                    txn,
                    *client_oid,
                )
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

/// Lock the issuing client row and re-derive its live authorization boundary.
///
/// The credential carries the original boundary fingerprint. A missing client,
/// a changed live boundary, or a stale fingerprint fails closed. Display text,
/// metadata and the client's UUID CAS version never participate; only real
/// authorization inputs do.
async fn recheck_issuing_client(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
) -> Result<(), RbacManagementRepositoryError> {
    let client_row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM client WHERE oid = $1 FOR UPDATE",
            [authority.client_oid.into()],
        ))
        .await
        .map_err(storage)?;
    let Some(client_row) = client_row else {
        return Err(RbacManagementRepositoryError::Authorization(
            ManagementAuthorizationError::NoCurrentGrant,
        ));
    };
    let client_id = client_row.try_get::<i64>("", "id").map_err(storage)?;
    let (_, fingerprint) =
        crate::database::client_authorization_boundary::client_boundary_fingerprint(txn, client_id)
            .await
            .map_err(storage)?;
    if fingerprint != authority.client_policy_version {
        return Err(RbacManagementRepositoryError::Authorization(
            ManagementAuthorizationError::SnapshotPolicyMismatch,
        ));
    }
    Ok(())
}

/// Re-verify entry authority with authoritative rows in the write transaction.
pub(crate) async fn recheck_authority(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    required: ManagementScope,
    target_user: Option<UserOid>,
) -> Result<CurrentManagementAuthority, RbacManagementRepositoryError> {
    crate::database::repository::authorization_lifecycle::lock_owner_lifecycle(txn)
        .await
        .map_err(storage)?;
    recheck_issuing_client(txn, authority).await?;
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

/// Sensitive policy switch: the exact required permission plus recent human
/// AAL2. There is deliberately no role/group membership gate; a custom role
/// containing the trusted permission works exactly like a built-in preset.
pub(crate) async fn recheck_owner_recent(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    required: ManagementScope,
) -> Result<(), RbacManagementRepositoryError> {
    recheck_authority(txn, authority, required, None).await?;
    let authentication = authority.actor.principal.human_authentication().ok_or(
        RbacManagementRepositoryError::Authorization(ManagementAuthorizationError::TargetForbidden),
    )?;
    let recent = authentication.is_recent_aal2(Utc::now(), DEFAULT_RECENT_AAL2_TTL);
    if !recent {
        return Err(RbacManagementRepositoryError::Authorization(
            ManagementAuthorizationError::RecentAuthenticationRequired,
        ));
    }
    Ok(())
}
