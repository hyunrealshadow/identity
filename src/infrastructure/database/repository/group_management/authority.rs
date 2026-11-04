//! Transaction-scoped group authority and delegation-ceiling reads.
//!
//! Group writes never load a legacy administrator binding. The actor's current
//! management permissions come from B's user-permission authority helper in the
//! same transaction; the delegation ceiling uses exactly those PRE-change
//! permissions.

use std::collections::BTreeSet;

use chrono::Utc;
use identity_application::{
    authorization::{
        CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError,
        ManagementAuthorizationRequest, ManagementTarget, evaluate_management_authority,
    },
    rbac::{GroupEntityKind, GroupManagementRepositoryError, RbacManagementAuthority},
};
use identity_domain::{
    authorization::{ActorPrincipal, ManagementScope, policy_fingerprint},
    user::UserOid,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::support::{Binds, corrupt, not_found, storage};

use crate::database::{
    client_authorization_boundary, repository::authorization::load_user_permission_authority,
};

/// Lock the issuing client row and re-derive its live authorization boundary.
///
/// The credential carries the original boundary fingerprint. A missing client,
/// a changed live boundary, or a stale fingerprint fails closed. Display text,
/// metadata and the client's UUID CAS version never participate.
async fn recheck_issuing_client(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
) -> Result<(), GroupManagementRepositoryError> {
    let client_row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM client WHERE oid = $1 FOR UPDATE",
            [authority.client_oid.into()],
        ))
        .await
        .map_err(storage)?;
    let Some(client_row) = client_row else {
        return Err(GroupManagementRepositoryError::Authorization(
            ManagementAuthorizationError::NoCurrentGrant,
        ));
    };
    let client_id = client_row.try_get::<i64>("", "id").map_err(storage)?;
    let (_, fingerprint) =
        client_authorization_boundary::client_boundary_fingerprint(txn, client_id)
            .await
            .map_err(storage)?;
    if fingerprint != authority.client_policy_version {
        return Err(GroupManagementRepositoryError::Authorization(
            ManagementAuthorizationError::SnapshotPolicyMismatch,
        ));
    }
    Ok(())
}

/// Re-check one exact group permission and return the actor's PRE-change
/// management permission set for the delegation ceiling.
pub(crate) async fn recheck_group_authority(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    required: ManagementScope,
) -> Result<BTreeSet<ManagementScope>, GroupManagementRepositoryError> {
    recheck_issuing_client(txn, authority).await?;
    let ActorPrincipal::User { user_oid, .. } = &authority.actor.principal else {
        return Err(GroupManagementRepositoryError::Authorization(
            ManagementAuthorizationError::HumanOnlyCapability { scope: required },
        ));
    };
    let Some(current) = load_user_permission_authority(txn, *user_oid)
        .await
        .map_err(storage)?
    else {
        return Err(GroupManagementRepositoryError::Authorization(
            ManagementAuthorizationError::NoCurrentGrant,
        ));
    };
    let permissions =
        effective_delegation_permissions(&current.permissions, &authority.token_scopes);
    let current = CurrentManagementAuthority::UserPermissions(current);
    let policy_version = policy_fingerprint();
    evaluate_management_authority(&ManagementAuthorizationRequest {
        actor: &authority.actor,
        token_scopes: &authority.token_scopes,
        required,
        target: ManagementTarget::instance(),
        current_authority: Some(&current),
        snapshot: authority.snapshot.as_ref(),
        credential_client_boundary: Some(authority.client_policy_version),
        current_policy_version: policy_version,
        now: Utc::now(),
        recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
    })
    .map_err(GroupManagementRepositoryError::Authorization)?;
    Ok(permissions)
}

/// Explicit delegation is a two-key capability.
///
/// The permission is only usable for grants outside the actor's own permission
/// ids when both the original token scopes and the live effective authority
/// carry `management.permission.delegate`. Missing either key falls back to the
/// pre-change subset rule. A client cannot add the capability to a token that
/// never had it, and a revoked live capability cannot be restored from the
/// token.
#[must_use]
pub(crate) fn effective_delegation_permissions(
    live: &BTreeSet<ManagementScope>,
    token_scopes: &BTreeSet<ManagementScope>,
) -> BTreeSet<ManagementScope> {
    let mut permissions = live.clone();
    if !token_scopes.contains(&ManagementScope::PermissionDelegate) {
        permissions.remove(&ManagementScope::PermissionDelegate);
    }
    permissions
}

/// Management scopes reachable through one explicit set of enabled roles.
///
/// Only trusted built-in management permissions on the Identity GraphQL
/// resource contribute. A custom permission cannot acquire management meaning
/// merely by carrying a `management.*` scope name.
pub(crate) async fn management_scopes_for_roles<C: ConnectionTrait>(
    db: &C,
    role_ids: &[i64],
) -> Result<BTreeSet<ManagementScope>, GroupManagementRepositoryError> {
    if role_ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut binds = Binds::new();
    let placeholders = role_ids
        .iter()
        .map(|id| binds.push(*id))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT DISTINCT s.code AS scope_code \
                 FROM role_permission rp \
                 JOIN \"scope\" s ON s.id = rp.scope_id \
                   AND s.enabled = true AND s.built_in = true \
                 JOIN resource res ON res.oid = s.resource_id \
                   AND res.uri = 'urn:identity:graphql' \
                 JOIN \"role\" r ON r.id = rp.role_id AND r.enabled = true \
                 WHERE rp.role_id IN ({placeholders})"
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?;
    let mut scopes = BTreeSet::new();
    for row in rows {
        let name = row.try_get::<String>("", "scope_code").map_err(storage)?;
        let scope = ManagementScope::from_name(&name).ok_or_else(corrupt)?;
        scopes.insert(scope);
    }
    Ok(scopes)
}

/// Management scopes currently reachable through a group's active role
/// bindings. Used when adding a member, enabling a group or creating a grant
/// that must stay inside the actor's delegation ceiling.
pub(crate) async fn management_scopes_for_group<C: ConnectionTrait>(
    db: &C,
    group_id: i64,
) -> Result<BTreeSet<ManagementScope>, GroupManagementRepositoryError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT DISTINCT s.code AS scope_code \
              FROM group_role grb \
              JOIN \"role\" r ON r.id = grb.role_id AND r.enabled = true \
              JOIN role_permission rp ON rp.role_id = r.id \
              JOIN \"scope\" s ON s.id = rp.scope_id \
                AND s.enabled = true AND s.built_in = true \
              JOIN resource res ON res.oid = s.resource_id \
                AND res.uri = 'urn:identity:graphql' \
              WHERE grb.group_id = $1 AND grb.enabled = true AND grb.revoked_at IS NULL",
            [group_id.into()],
        ))
        .await
        .map_err(storage)?;
    let mut scopes = BTreeSet::new();
    for row in rows {
        let name = row.try_get::<String>("", "scope_code").map_err(storage)?;
        let scope = ManagementScope::from_name(&name).ok_or_else(corrupt)?;
        scopes.insert(scope);
    }
    Ok(scopes)
}

/// `actor` must already be the intersection of the live effective authority and
/// the original token scopes produced by [`effective_delegation_permissions`].
/// Callers must not pass an unfiltered live set: that would let a token without
/// the delegation scope bypass the ceiling.
pub(crate) fn ensure_delegation_subset(
    actor: &BTreeSet<ManagementScope>,
    proposed: &BTreeSet<ManagementScope>,
) -> Result<(), GroupManagementRepositoryError> {
    if actor.contains(&ManagementScope::PermissionDelegate) {
        return Ok(());
    }
    if let Some(scope) = proposed.difference(actor).next() {
        return Err(GroupManagementRepositoryError::DelegationCeilingExceeded {
            scope: scope.name().to_owned(),
        });
    }
    Ok(())
}

/// Every permission row currently reachable by the actor through active direct
/// or group role paths. This is the PRE-change delegation set for all resources,
/// not only the management GraphQL resource.
pub(crate) async fn actor_effective_permission_ids(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
) -> Result<BTreeSet<i64>, GroupManagementRepositoryError> {
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT DISTINCT scope_row.id AS permission_id
FROM "user" subject
JOIN user_role binding
  ON binding.user_id = subject.id AND binding.enabled = true AND binding.revoked_at IS NULL
JOIN "role" role_row ON role_row.id = binding.role_id AND role_row.enabled = true
JOIN role_permission membership ON membership.role_id = role_row.id
JOIN "scope" scope_row ON scope_row.id = membership.scope_id AND scope_row.enabled = true
WHERE subject.oid = $1
UNION
SELECT DISTINCT scope_row.id
FROM "user" subject
JOIN group_membership member
  ON member.user_id = subject.id AND member.enabled = true AND member.revoked_at IS NULL
JOIN user_group group_row ON group_row.id = member.group_id AND group_row.enabled = true
JOIN group_role relation
  ON relation.group_id = group_row.id AND relation.enabled = true AND relation.revoked_at IS NULL
JOIN "role" role_row ON role_row.id = relation.role_id AND role_row.enabled = true
JOIN role_permission membership ON membership.role_id = role_row.id
JOIN "scope" scope_row ON scope_row.id = membership.scope_id AND scope_row.enabled = true
WHERE subject.oid = $1
"#,
            [Uuid::from(user_oid).into()],
        ))
        .await
        .map_err(storage)?;
    let mut ids = BTreeSet::new();
    for row in rows {
        ids.insert(row.try_get::<i64>("", "permission_id").map_err(storage)?);
    }
    Ok(ids)
}

pub(crate) async fn group_permission_ids<C: ConnectionTrait>(
    db: &C,
    group_id: i64,
) -> Result<BTreeSet<i64>, GroupManagementRepositoryError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT DISTINCT rp.scope_id \
             FROM group_role grb \
             JOIN \"role\" r ON r.id = grb.role_id AND r.enabled = true \
             JOIN role_permission rp ON rp.role_id = r.id \
             JOIN \"scope\" scope_row ON scope_row.id = rp.scope_id AND scope_row.enabled = true \
             WHERE grb.group_id = $1 AND grb.enabled = true AND grb.revoked_at IS NULL",
            [group_id.into()],
        ))
        .await
        .map_err(storage)?;
    rows.into_iter()
        .map(|row| row.try_get::<i64>("", "scope_id").map_err(storage))
        .collect()
}

pub(crate) async fn roles_permission_ids<C: ConnectionTrait>(
    db: &C,
    role_ids: &[i64],
) -> Result<BTreeSet<i64>, GroupManagementRepositoryError> {
    if role_ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut binds = Binds::new();
    let placeholders = role_ids
        .iter()
        .map(|id| binds.push(*id))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT DISTINCT rp.scope_id \
                 FROM \"role\" r \
                 JOIN role_permission rp ON rp.role_id = r.id \
                 JOIN \"scope\" scope_row ON scope_row.id = rp.scope_id \
                   AND scope_row.enabled = true \
                 WHERE r.id IN ({placeholders}) AND r.enabled = true"
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?;
    rows.into_iter()
        .map(|row| row.try_get::<i64>("", "scope_id").map_err(storage))
        .collect()
}

pub(crate) async fn ensure_delegable_permission_ids(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
    proposed: &BTreeSet<i64>,
    explicitly_delegable: bool,
) -> Result<(), GroupManagementRepositoryError> {
    if proposed.is_empty() || explicitly_delegable {
        return Ok(());
    }
    let effective = actor_effective_permission_ids(txn, user_oid).await?;
    let missing: Vec<i64> = proposed.difference(&effective).copied().collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut binds = Binds::new();
    let placeholders = missing
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
    Err(GroupManagementRepositoryError::DelegationCeilingExceeded {
        scope: row.try_get::<String>("", "code").map_err(storage)?,
    })
}

pub(crate) fn require_actor_user(
    authority: &RbacManagementAuthority,
    scope: ManagementScope,
) -> Result<UserOid, GroupManagementRepositoryError> {
    actor_user_id(authority).ok_or(GroupManagementRepositoryError::Authorization(
        ManagementAuthorizationError::HumanOnlyCapability { scope },
    ))
}

pub(crate) async fn lock_user_id<C: ConnectionTrait>(
    db: &C,
    user_oid: UserOid,
) -> Result<i64, GroupManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM \"user\" WHERE oid = $1 FOR UPDATE",
            [Uuid::from(user_oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.ok_or_else(|| not_found(GroupEntityKind::User))?
        .try_get::<i64>("", "id")
        .map_err(storage)
}

pub(crate) fn actor_user_id(authority: &RbacManagementAuthority) -> Option<UserOid> {
    match &authority.actor.principal {
        ActorPrincipal::User { user_oid, .. } => Some(*user_oid),
        ActorPrincipal::Client { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{TimeZone, Utc};
    use identity_application::authorization::{
        CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationError,
        ManagementAuthorizationRequest, ManagementTarget, evaluate_management_authority,
    };
    use identity_domain::{
        authorization::{
            ManagementScope,
            actor::{ActorContext, HumanAuthenticationContext, RequestId},
            authority::UserPermissionAuthority,
            ids::{AuthorizationVersion, PolicyVersion},
            snapshot::ManagementAuthorizationSnapshot,
        },
        user::UserOid,
    };
    use uuid::Uuid;

    use super::effective_delegation_permissions;

    fn scopes(scopes: &[ManagementScope]) -> BTreeSet<ManagementScope> {
        scopes.iter().copied().collect()
    }

    #[test]
    fn explicit_delegation_requires_token_and_live_capability() {
        let live = scopes(&[
            ManagementScope::GroupsWrite,
            ManagementScope::PermissionDelegate,
        ]);
        let token_with = scopes(&[
            ManagementScope::GroupsWrite,
            ManagementScope::PermissionDelegate,
        ]);
        let token_without = scopes(&[ManagementScope::GroupsWrite]);

        assert!(
            effective_delegation_permissions(&live, &token_with)
                .contains(&ManagementScope::PermissionDelegate)
        );
        assert!(
            !effective_delegation_permissions(&live, &token_without)
                .contains(&ManagementScope::PermissionDelegate)
        );
        assert!(
            !effective_delegation_permissions(
                &scopes(&[ManagementScope::GroupsWrite]),
                &token_with
            )
            .contains(&ManagementScope::PermissionDelegate)
        );

        // A token that never carried the delegate scope cannot bypass the
        // pre-change subset ceiling for a scope the live actor does not hold.
        let stripped = effective_delegation_permissions(&live, &token_without);
        assert!(
            super::ensure_delegation_subset(
                &stripped,
                &scopes(&[ManagementScope::GroupRolesWrite])
            )
            .is_err()
        );
    }

    #[test]
    fn absent_delegation_keeps_the_pre_change_subset_rule() {
        let live = scopes(&[ManagementScope::GroupsWrite]);
        let token = scopes(&[ManagementScope::GroupsWrite]);
        let effective = effective_delegation_permissions(&live, &token);
        assert_eq!(effective, live);
        assert!(!effective.contains(&ManagementScope::PermissionDelegate));
    }

    #[test]
    fn group_write_rejects_a_stale_authorization_snapshot() {
        let user = UserOid(Uuid::new_v4());
        let issued = UserPermissionAuthority::new(
            user,
            AuthorizationVersion::fresh(),
            [ManagementScope::GroupRolesWrite],
        );
        let policy_version = PolicyVersion::fresh();
        let snapshot =
            ManagementAuthorizationSnapshot::for_user_permissions(&issued, policy_version);
        let current = UserPermissionAuthority::new(
            user,
            AuthorizationVersion::fresh(),
            [ManagementScope::GroupRolesWrite],
        );
        let current = CurrentManagementAuthority::UserPermissions(current);
        let actor = ActorContext::for_user(
            user,
            HumanAuthenticationContext::aal2(None),
            RequestId::new("group-stale-snapshot").expect("request id"),
            None,
        );
        let token_scopes = scopes(&[ManagementScope::GroupRolesWrite]);
        let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
        let request = ManagementAuthorizationRequest {
            actor: &actor,
            token_scopes: &token_scopes,
            required: ManagementScope::GroupRolesWrite,
            target: ManagementTarget::instance(),
            current_authority: Some(&current),
            snapshot: Some(&snapshot),
            credential_client_boundary: None,
            current_policy_version: policy_version,
            now,
            recent_aal2_ttl: DEFAULT_RECENT_AAL2_TTL,
        };
        assert!(matches!(
            evaluate_management_authority(&request),
            Err(ManagementAuthorizationError::SnapshotStale { .. })
        ));
    }
}
