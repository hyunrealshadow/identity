//! Transaction-scoped Rust implementations of authorization lifecycle
//! invariants.
//!
//! These rules used to be enforced by PostgreSQL triggers. They now live here so
//! every business write can acquire the same locks, read authoritative state and
//! mutate within one transaction. Callers must already own the transaction.
//!
//! Lock order for authorization-sensitive work:
//! 1. `owner_lifecycle` advisory lock (global, cross-entry serialization; the
//!    historical name is retained for compatibility with existing callers)
//! 2. target resource rows
//! 3. account credential advisory lock, then subject row
//! 4. session advisory locks, then issuing client and parent artifact
//!
//! Recovery protection is capability-based: it counts enabled users whose
//! effective trusted permission set is complete and who hold a usable login
//! credential. Role keys, display names and built-in group membership are never
//! consulted.

use identity_domain::{
    authorization::{
        authority::{UserPermissionAuthority, full_management_permissions},
        ids::AuthorizationVersion,
        recovery::OwnerAccessSnapshot,
    },
    user::UserOid,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, EntityTrait, QueryFilter,
    Statement, sea_query::Expr,
};
use uuid::Uuid;

use crate::database::{entity::user, query::advisory_transaction_lock};

pub(crate) const OWNER_LIFECYCLE_LOCK_ID: i64 = 0x4F57_4E45_524C_0001;

/// Allow concurrent issuance while serializing it against authorization graph
/// writes. Acquire before resource, subject or client locks so graph writers
/// cannot hold an actor/client row while waiting for an issuance resource row.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "lock_authorization_issuance"))]
pub(crate) async fn lock_authorization_issuance(txn: &DatabaseTransaction) -> Result<(), DbErr> {
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT pg_advisory_xact_lock_shared($1)",
        [OWNER_LIFECYCLE_LOCK_ID.into()],
    ))
    .await?;
    Ok(())
}

/// Acquire the global authorization-lifecycle serialization lock. Callers must
/// do this before reading authority facts. There is no mutable policy-state row
/// to stamp: snapshots bind to the derived catalog fingerprint instead.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "lock_owner_lifecycle"))]
pub(crate) async fn lock_owner_lifecycle(txn: &DatabaseTransaction) -> Result<(), DbErr> {
    txn.execute(&advisory_transaction_lock(Expr::value(
        OWNER_LIFECYCLE_LOCK_ID,
    )))
    .await?;
    Ok(())
}

/// Rotate the core user UUID optimistic-lock token; a successful write stores one
/// fresh UUID and never reuses an earlier value.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "renew_user_version"))]
pub(crate) async fn renew_user_version_in_txn(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<AuthorizationVersion, DbErr> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
UPDATE "user"
SET version = gen_random_uuid(), updated_at = now()
WHERE id = $1
RETURNING version
"#,
            [user_id.into()],
        ))
        .await?
        .ok_or_else(|| DbErr::Custom("user version target is missing".to_owned()))?;
    let version = row.try_get::<Uuid>("", "version")?;
    Ok(AuthorizationVersion::from_uuid(version))
}

/// Permanently withdraw every existing authorization artifact owned by a user.
///
/// This is distinct from [`renew_user_version_in_txn`], which is optimistic-lock
/// bookkeeping only. A real authority-changing event must rotate the user CAS
/// token *and* tombstone all already-issued artifacts: queued/approved device
/// requests, authorization requests, codes, access tokens and refresh tokens,
/// including rows that were already consumed or revoked as single-use parents.
/// The `_authority_withdrawn` JSON marker is never cleared, so disable/enable,
/// lock/unlock and remove/re-add cycles cannot revive old credentials.
///
/// Matching is limited to the subject: explicit `user_oid`, device
/// `approval.user_oid`, interactions/artifacts bound to one of the user's
/// sessions, queued device requests claimed by one of the user's logins, and
/// tokens linked to that user's device authorization relations. Client-only
/// artifacts without a subject link are preserved.
///
/// The CAS rotation deliberately runs first. Every issuance path locks the user
/// row `FOR SHARE` before reading the authority fingerprint and inserting
/// artifacts, so a concurrent issuance either commits before the CAS write (and
/// is then visible to the following artifact UPDATE) or blocks until this
/// transaction commits. That closes the consume-then-withdraw window where a
/// newly minted child could otherwise escape tombstoning.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "withdraw_user_authority"))]
pub(crate) async fn withdraw_user_authority_in_txn(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<AuthorizationVersion, DbErr> {
    let version = renew_user_version_in_txn(txn, user_id).await?;
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
WITH subject AS (
    SELECT u.id, u.oid,
           ARRAY(
               SELECT s.oid::text FROM session s WHERE s.user_id = u.id
           ) AS session_oids
    FROM "user" u
    WHERE u.id = $1
)
UPDATE client_authorization artifact
SET revoked_at = COALESCE(artifact.revoked_at, now()),
    updated_at = now(),
    data = jsonb_set(artifact.data, '{_authority_withdrawn}', 'true'::jsonb, true)
FROM subject
WHERE subject.id = $1
  AND (
      artifact.data->>'user_oid' = subject.oid::text
      OR artifact.data#>>'{approval,user_oid}' = subject.oid::text
      OR artifact.data#>>'{interaction,selected_user_oid}' = subject.oid::text
      OR artifact.data->>'session_oid' = ANY(subject.session_oids)
      OR artifact.data#>>'{interaction,selected_session_oid}' = ANY(subject.session_oids)
      OR artifact.data->>'claimed_login_oid' IN (
          SELECT login.oid::text FROM login WHERE login.user_id = subject.id
      )
      OR artifact.data->>'device_authorization_oid' IN (
          SELECT relation.oid::text
          FROM client_authorization relation
          WHERE relation.type = 'device_authorization'
            AND relation.data->>'user_oid' = subject.oid::text
      )
  )
"#,
        [user_id.into()],
    ))
    .await?;
    Ok(version)
}

/// When an account's enabled/locked state or credential set changes, rotate the
/// CAS token and permanently withdraw every existing subject credential. This
/// runs on both withdrawal and restoration transitions; the marker makes the
/// withdrawal one-way even though the account becomes available again.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "sync_user_authority"))]
pub(crate) async fn sync_user_authority_in_txn(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<AuthorizationVersion, DbErr> {
    withdraw_user_authority_in_txn(txn, user_id).await
}

/// Candidate users with enough effective management permissions. This is only a
/// cheap prefilter; every candidate is revalidated through the trusted identity
/// loader before it counts as recoverable.
const RECOVERABLE_CANDIDATE_SQL: &str = r#"
WITH candidates AS (
    SELECT u.id, u.oid
    FROM "user" u
    WHERE u.enabled = true
      AND (NOT u.locked OR u.locked_until IS NOT NULL)
      AND EXISTS (
          SELECT 1 FROM user_credential uc
          WHERE uc.user_id = u.id
            AND uc.type IN ('password', 'passkey')
            AND (uc.expires_at IS NULL OR uc.expires_at > now())
      )
),
effective AS (
    SELECT urb.user_id AS user_id, scope.oid AS permission_oid,
           scope.enabled AS permission_enabled, scope.built_in AS permission_built_in,
           resource.uri AS resource_uri
    FROM user_role_binding urb
    JOIN "role" rl ON rl.id = urb.role_id
    JOIN role_permission rpr ON rpr.role_id = rl.id
    JOIN scope ON scope.id = rpr.scope_id
    JOIN resource ON resource.oid = scope.resource_id AND resource.enabled = true
    WHERE urb.enabled = true AND urb.revoked_at IS NULL AND rl.enabled = true
    UNION
    SELECT gm.user_id, scope.oid, scope.enabled, scope.built_in, resource.uri
    FROM group_membership gm
    JOIN user_group ug ON ug.id = gm.group_id
    JOIN group_role_binding grb ON grb.group_id = ug.id
    JOIN "role" rl ON rl.id = grb.role_id
    JOIN role_permission rpr ON rpr.role_id = rl.id
    JOIN scope ON scope.id = rpr.scope_id
    JOIN resource ON resource.oid = scope.resource_id AND resource.enabled = true
    WHERE gm.enabled = true AND gm.revoked_at IS NULL
      AND ug.enabled = true AND ug.deleted_at IS NULL
      AND grb.enabled = true AND grb.revoked_at IS NULL
      AND rl.enabled = true
)
SELECT c.id, c.oid
FROM candidates c
WHERE (
    SELECT count(DISTINCT e.permission_oid)
    FROM effective e
    WHERE e.user_id = c.id
      AND e.resource_uri = 'urn:identity:graphql'
      AND e.permission_enabled = true
      AND e.permission_built_in = true
) >= $1
"#;

/// The exact capability a recoverable authorization administrator must hold.
#[must_use]
pub(crate) fn target_permissions()
-> std::collections::BTreeSet<identity_domain::authorization::ManagementScope> {
    full_management_permissions()
}

fn is_recoverable_full_authority(authority: &UserPermissionAuthority) -> bool {
    authority.has_full_management_permissions()
}

/// Ensure at least one recoverable authorization administrator remains.
///
/// Call this AFTER the proposed authorization/account/credential mutation and
/// BEFORE audit/commit, while holding [`lock_owner_lifecycle`]. It sees the
/// transaction's own updates. It returns an error when no enabled user with a
/// usable credential holds the exact complete trusted management permission
/// set. Temporary finite automatic locks still count as recoverable; permanent
/// lock/disablement or credential loss does not.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "ensure_recoverable_authorization_administrator"))]
pub(crate) async fn ensure_recoverable_authorization_administrator(
    txn: &DatabaseTransaction,
) -> Result<(), DbErr> {
    let full = target_permissions();
    let minimum = full.len() as i64;
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            RECOVERABLE_CANDIDATE_SQL,
            [minimum.into()],
        ))
        .await?;
    for row in rows {
        let oid = row.try_get::<Uuid>("", "oid")?;
        let authority = crate::database::repository::authorization::load_user_permission_authority(
            txn,
            identity_domain::user::UserOid(oid),
        )
        .await?;
        if authority
            .as_ref()
            .is_some_and(is_recoverable_full_authority)
        {
            return Ok(());
        }
    }
    Err(DbErr::Custom(
        "no recoverable authorization administrator remains".to_owned(),
    ))
}

/// Recovery facts for the `OwnerRecoverabilityPort` compatibility adapter.
///
/// `target_is_active_owner` now means "target holds the full trusted management
/// capability set", never membership in a fixed role.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "recoverable_authorization_snapshot"))]
pub(crate) async fn recoverable_authorization_snapshot_in_txn(
    txn: &DatabaseTransaction,
    target: UserOid,
) -> Result<OwnerAccessSnapshot, DbErr> {
    let target_row = user::Entity::find()
        .filter(user::Column::Oid.eq(target.0))
        .one(txn)
        .await?
        .ok_or_else(|| DbErr::Custom("recoverable authorization target is missing".to_owned()))?;

    let target_credential = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT EXISTS (
    SELECT 1 FROM user_credential uc
    WHERE uc.user_id = $1
      AND uc.type IN ('password', 'passkey')
      AND (uc.expires_at IS NULL OR uc.expires_at > now())
) AS present
"#,
            [target_row.id.into()],
        ))
        .await?
        .and_then(|row| row.try_get::<bool>("", "present").ok())
        .unwrap_or(false);

    let target_is_active_owner =
        crate::database::repository::authorization::load_user_permission_authority(txn, target)
            .await?
            .is_some_and(|authority| authority.has_full_management_permissions());

    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            RECOVERABLE_CANDIDATE_SQL,
            [(target_permissions().len() as i64).into()],
        ))
        .await?;
    let mut other_active_owner_count = 0u64;
    let mut other_usable_owner_count = 0u64;
    for row in rows {
        let oid = row.try_get::<Uuid>("", "oid")?;
        if oid == target.0 {
            continue;
        }
        let authority = crate::database::repository::authorization::load_user_permission_authority(
            txn,
            UserOid(oid),
        )
        .await?;
        if authority
            .as_ref()
            .is_some_and(|authority| authority.has_full_management_permissions())
        {
            other_active_owner_count += 1;
            // The candidate SQL already requires an enabled, not-permanently
            // locked user with a usable credential.
            other_usable_owner_count += 1;
        }
    }

    Ok(OwnerAccessSnapshot {
        target_user_enabled: target_row.enabled,
        target_has_recoverable_credential: target_credential
            && (!target_row.locked || target_row.locked_until.is_some()),
        target_is_active_owner,
        other_active_owner_count,
        other_usable_owner_count,
    })
}
