//! Pre-change delegation ceiling and trusted built-in permission reference
//! checks for RBAC mutations.
//!
//! The actor's authoritative effective permissions are read from the same
//! direct and group relation tables used for runtime authorization. They are
//! read before the proposed write, so a mutation cannot use the permissions it
//! is about to create to authorize itself.

use std::collections::BTreeSet;

use chrono::Utc;
use identity_application::{
    authorization::{DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError},
    rbac::{RbacManagementAuthority, RbacManagementRepositoryError, ScopeOid},
};
use identity_domain::{
    authorization::{ActorPrincipal, ManagementScope},
    openid_connect::API_RESOURCE,
    rbac,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::support::{Binds, corrupt, storage};
use crate::database::repository::authorization;

/// Effective permission row IDs currently held by the actor through active
/// direct bindings or active group paths.
pub(crate) async fn actor_effective_permission_ids(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
) -> Result<BTreeSet<i64>, RbacManagementRepositoryError> {
    let user_oid = match &authority.actor.principal {
        ActorPrincipal::User { user_oid, .. } => *user_oid,
        // Management RBAC writes that change authority are human-only. A
        // machine continuation cannot establish a delegation ceiling here.
        ActorPrincipal::Client { .. } => return Ok(BTreeSet::new()),
    };
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT DISTINCT scope_row.id AS scope_id
FROM "user" subject
JOIN user_role binding
  ON binding.user_id = subject.id AND binding.enabled = true AND binding.revoked_at IS NULL
JOIN "role" role_row ON role_row.id = binding.role_id AND role_row.enabled = true
JOIN role_permission membership ON membership.role_id = role_row.id
JOIN "scope" scope_row
  ON scope_row.id = membership.scope_id AND scope_row.enabled = true
WHERE subject.oid = $1
UNION
SELECT DISTINCT scope_row.id
FROM "user" subject
JOIN group_membership group_member
  ON group_member.user_id = subject.id
 AND group_member.enabled = true AND group_member.revoked_at IS NULL
JOIN user_group user_group_row
  ON user_group_row.id = group_member.group_id AND user_group_row.enabled = true
JOIN group_role group_relation
  ON group_relation.group_id = user_group_row.id
 AND group_relation.enabled = true AND group_relation.revoked_at IS NULL
JOIN "role" role_row ON role_row.id = group_relation.role_id AND role_row.enabled = true
JOIN role_permission membership ON membership.role_id = role_row.id
JOIN "scope" scope_row
  ON scope_row.id = membership.scope_id AND scope_row.enabled = true
WHERE subject.oid = $1
"#,
            [Uuid::from(user_oid).into()],
        ))
        .await
        .map_err(storage)?;
    let mut ids = BTreeSet::new();
    for row in rows {
        ids.insert(row.try_get::<i64>("", "scope_id").map_err(storage)?);
    }
    Ok(ids)
}

/// Reject any newly added permission ID outside the actor's pre-change
/// effective permission set. Removing authority is not gated by this ceiling.
pub(crate) async fn ensure_delegable_permissions(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    added_permission_ids: &BTreeSet<i64>,
) -> Result<(), RbacManagementRepositoryError> {
    if added_permission_ids.is_empty() {
        return Ok(());
    }
    let effective = actor_effective_permission_ids(txn, authority).await?;
    let unauthorized: Vec<i64> = added_permission_ids
        .iter()
        .filter(|id| !effective.contains(id))
        .copied()
        .collect();
    if unauthorized.is_empty() {
        return Ok(());
    }
    if authority
        .token_scopes
        .contains(&ManagementScope::PermissionDelegate)
        && let ActorPrincipal::User { user_oid, .. } = &authority.actor.principal
    {
        let current = authorization::load_user_permission_authority(txn, *user_oid)
            .await
            .map_err(storage)?;
        if current.is_some_and(|current| {
            current
                .permissions
                .contains(&ManagementScope::PermissionDelegate)
        }) {
            if !authority
                .actor
                .principal
                .human_authentication()
                .is_some_and(|authentication| {
                    authentication.is_recent_aal2(Utc::now(), DEFAULT_RECENT_AAL2_TTL)
                })
            {
                return Err(RbacManagementRepositoryError::Authorization(
                    ManagementAuthorizationError::RecentAuthenticationRequired,
                ));
            }
            return Ok(());
        }
    }
    let mut binds = Binds::new();
    let placeholders = unauthorized
        .iter()
        .map(|id| binds.push(*id))
        .collect::<Vec<_>>()
        .join(", ");
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT code FROM \"scope\" WHERE id IN ({placeholders}) \
                 ORDER BY id LIMIT 1"
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
    Err(RbacManagementRepositoryError::DelegationCeilingExceeded {
        permission: row.try_get::<String>("", "code").map_err(storage)?,
    })
}

/// Validate references to trusted built-in scope rows.
///
/// A custom role may reference a built-in management scope, but the row must
/// still match the compiled catalog: the deterministic scope OID, exact code,
/// built-in flag and the reserved first-party API resource. A database flag
/// alone never creates a capability.
pub(crate) async fn validate_built_in_permission_references(
    txn: &DatabaseTransaction,
    scope_oids: &[ScopeOid],
) -> Result<(), RbacManagementRepositoryError> {
    if scope_oids.is_empty() {
        return Ok(());
    }
    let mut binds = Binds::new();
    let placeholders = scope_oids
        .iter()
        .map(|oid| binds.push(oid.0))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                r#"
SELECT scope.oid, scope.code AS scope_code, scope.built_in,
       resource_row.uri AS resource_uri
FROM "scope" scope
LEFT JOIN resource resource_row ON resource_row.oid = scope.resource_id
WHERE scope.oid IN ({placeholders})
"#
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?;
    for row in rows {
        let built_in = row.try_get::<bool>("", "built_in").map_err(storage)?;
        if !built_in {
            continue;
        }
        let scope = row.try_get::<String>("", "scope_code").map_err(storage)?;
        let resource_uri = row
            .try_get::<Option<String>>("", "resource_uri")
            .map_err(storage)?;
        let oid = row.try_get::<Uuid>("", "oid").map_err(storage)?;
        let trusted = ManagementScope::from_name(&scope).is_some_and(|management_scope| {
            rbac::built_in_permission_oid(management_scope).0 == oid
        }) && resource_uri.as_deref() == Some(API_RESOURCE);
        if !trusted {
            return Err(
                RbacManagementRepositoryError::InvalidBuiltInPermissionReference {
                    permission: scope,
                },
            );
        }
    }
    Ok(())
}
