//! Transactional group writes.
//!
//! Lock order: existing authorization lifecycle lock, issuing client policy,
//! actor authority, group row, role rows, affected user rows, relation rows.
//! Every removal tombstones the old OID; every new grant inserts a fresh OID.
//! Group/relation versions are UUID change tokens; no numeric counters exist.

use std::collections::{BTreeMap, BTreeSet};

use identity_application::rbac::{
    AddGroupMemberTransaction, CreateGroupTransaction, DeleteGroupResult, DeleteGroupTransaction,
    GroupEntityKind, GroupManagementRepositoryError, GroupMembershipMutationResult, GroupRecord,
    GroupRoleMutationResult, GroupStateTransaction, RemoveGroupMemberTransaction,
    SetGroupRolesTransaction, UpdateGroupTransaction,
};
use identity_domain::{
    authorization::ManagementScope,
    rbac::{GroupMembershipOid, GroupRoleOid, LocalizedMetadata, LocalizedTextError, RoleOid},
    user::UserOid,
};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, Statement, TransactionTrait, Value,
};
use uuid::Uuid;

use super::{
    GroupManagementRepositoryImpl,
    audit::append_semantic_audit,
    authority::{
        actor_user_id, ensure_delegable_permission_ids, ensure_delegation_subset,
        group_permission_ids, lock_user_id, management_scopes_for_group,
        management_scopes_for_roles, recheck_group_authority, require_actor_user,
        roles_permission_ids,
    },
    query::{
        GROUP_SELECT, group_from_row, group_id_by_oid_locked, load_group_by_id_locked,
        load_membership_by_oid,
    },
    support::{Binds, corrupt, localized_json, not_found, storage},
};

use crate::database::repository::authorization_lifecycle::{
    ensure_recoverable_authorization_administrator, lock_owner_lifecycle,
    withdraw_user_authority_in_txn,
};

fn invalid_localized(error: LocalizedTextError) -> GroupManagementRepositoryError {
    let field = match error {
        LocalizedTextError::InvalidLocale { .. } => "names.locale",
        LocalizedTextError::DuplicateLocale { .. }
        | LocalizedTextError::EmptyName { .. }
        | LocalizedTextError::TextTooLong { .. }
        | LocalizedTextError::TooManyEntries { .. } => "names",
    };
    GroupManagementRepositoryError::InvalidMetadata {
        field: field.to_owned(),
    }
}

fn check_version(current: Uuid, expected: Uuid) -> Result<(), GroupManagementRepositoryError> {
    if current != expected {
        return Err(GroupManagementRepositoryError::VersionConflict {
            current_version: current,
        });
    }
    Ok(())
}

/// Added and removed role ids for a requested role set. An identical set yields
/// two empty vectors, which is the caller's no-op signal and must not bump the
/// group version.
fn role_binding_changes(current: &BTreeSet<i64>, proposed: &BTreeSet<i64>) -> (Vec<i64>, Vec<i64>) {
    (
        proposed.difference(current).copied().collect(),
        current.difference(proposed).copied().collect(),
    )
}

async fn renew_group_version(
    txn: &DatabaseTransaction,
    group_id: i64,
) -> Result<Uuid, GroupManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE user_group SET version = gen_random_uuid(), updated_at = now() \
             WHERE id = $1 RETURNING version",
            [group_id.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
    row.try_get::<Uuid>("", "version").map_err(storage)
}

const RECOVERY_PROTECTED_MESSAGE: &str = "no recoverable authorization administrator remains";

async fn ensure_recovery(txn: &DatabaseTransaction) -> Result<(), GroupManagementRepositoryError> {
    ensure_recoverable_authorization_administrator(txn)
        .await
        .map_err(map_recovery_error)
}

/// Only the explicit protection result is a business conflict. Any other
/// database failure must remain a storage failure instead of claiming that the
/// last administrator check failed.
fn map_recovery_error(error: DbErr) -> GroupManagementRepositoryError {
    if matches!(&error, DbErr::Custom(message) if message == RECOVERY_PROTECTED_MESSAGE) {
        return GroupManagementRepositoryError::LastRecoveryProtected;
    }
    storage(error)
}

async fn active_member_ids(
    txn: &DatabaseTransaction,
    group_id: i64,
) -> Result<Vec<i64>, GroupManagementRepositoryError> {
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT DISTINCT user_id FROM group_membership \
             WHERE group_id = $1 AND enabled = true AND revoked_at IS NULL \
             ORDER BY user_id",
            [group_id.into()],
        ))
        .await
        .map_err(storage)?;
    rows.into_iter()
        .map(|row| row.try_get::<i64>("", "user_id").map_err(storage))
        .collect()
}

async fn renew_members(
    txn: &DatabaseTransaction,
    group_id: i64,
) -> Result<(), GroupManagementRepositoryError> {
    for user_id in active_member_ids(txn, group_id).await? {
        withdraw_user_authority_in_txn(txn, user_id)
            .await
            .map_err(storage)?;
    }
    Ok(())
}

async fn non_locking_user_id(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
) -> Result<Option<i64>, GroupManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM \"user\" WHERE oid = $1",
            [Uuid::from(user_oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.map(|row| row.try_get::<i64>("", "id").map_err(storage))
        .transpose()
}

struct LockedRole {
    id: i64,
    oid: RoleOid,
    enabled: bool,
}

async fn lock_roles(
    txn: &DatabaseTransaction,
    role_oids: &[RoleOid],
) -> Result<Vec<LockedRole>, GroupManagementRepositoryError> {
    if role_oids.is_empty() {
        return Ok(Vec::new());
    }
    let mut binds = Binds::new();
    let placeholders = role_oids
        .iter()
        .map(|oid| binds.push(Uuid::from(*oid)))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT id, oid, enabled FROM \"role\" WHERE oid IN ({placeholders}) \
                 ORDER BY id FOR UPDATE"
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?;
    if rows.len() != role_oids.len() {
        return Err(GroupManagementRepositoryError::NotFound(
            GroupEntityKind::Role,
        ));
    }
    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        roles.push(LockedRole {
            id: row.try_get::<i64>("", "id").map_err(storage)?,
            oid: RoleOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
            enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        });
    }
    Ok(roles)
}

impl GroupManagementRepositoryImpl {
    pub(crate) async fn group_create(
        &self,
        command: CreateGroupTransaction,
    ) -> Result<GroupRecord, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let _actor_permissions =
            recheck_group_authority(&txn, &command.authority, ManagementScope::GroupsWrite).await?;
        let metadata =
            LocalizedMetadata::canonicalize(command.names.clone(), command.descriptions.clone())
                .map_err(invalid_localized)?;
        let names = localized_json(&metadata.names)?;
        let descriptions = localized_json(&metadata.descriptions)?;
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO user_group(oid, built_in, names, descriptions, name, description, \
                    enabled, version, created_at) \
                 VALUES($1, false, $2::jsonb, $3::jsonb, $4, $5, true, gen_random_uuid(), now()) \
                 RETURNING id",
                [
                    Uuid::from(command.group_oid).into(),
                    names.to_string().into(),
                    descriptions.to_string().into(),
                    command.name.into(),
                    command.description.into(),
                ],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let group_id = row.try_get::<i64>("", "id").map_err(storage)?;
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.group.create",
            "user_group",
            Uuid::from(command.group_oid),
            &command.reason,
        )
        .await?;
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("{GROUP_SELECT} WHERE ug.id = $1"),
                [group_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(GroupEntityKind::Group))?;
        let record = group_from_row(&row)?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn group_update(
        &self,
        command: UpdateGroupTransaction,
    ) -> Result<GroupRecord, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let _actor_permissions =
            recheck_group_authority(&txn, &command.authority, ManagementScope::GroupsWrite).await?;
        let group_id = group_id_by_oid_locked(&txn, command.group_oid).await?;
        let current = load_group_by_id_locked(&txn, group_id).await?;
        if current.built_in {
            return Err(GroupManagementRepositoryError::BuiltInProtected);
        }
        check_version(current.version, command.expected_version)?;
        if command.name.is_none()
            && command.description.is_none()
            && command.names.is_none()
            && command.descriptions.is_none()
        {
            return Err(GroupManagementRepositoryError::EmptyUpdate);
        }
        let metadata = LocalizedMetadata::canonicalize(
            command.names.unwrap_or_else(|| current.names.clone()),
            command
                .descriptions
                .unwrap_or_else(|| current.descriptions.clone()),
        )
        .map_err(invalid_localized)?;
        let name = command.name.unwrap_or_else(|| current.name.clone());
        let description = command
            .description
            .unwrap_or_else(|| current.description.clone());
        let unchanged = name == current.name
            && description == current.description
            && metadata.names == current.names
            && metadata.descriptions == current.descriptions;
        if unchanged {
            // Re-submitting the same definition is not a change. Metadata edits
            // never renew member authority.
            txn.commit().await.map_err(storage)?;
            return Ok(current);
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE user_group SET names = $2::jsonb, descriptions = $3::jsonb, name = $4, description = $5, \
              version = gen_random_uuid(), updated_at = now() WHERE id = $1",
            [
                group_id.into(),
                localized_json(&metadata.names)?.to_string().into(),
                localized_json(&metadata.descriptions)?.to_string().into(),
                name.into(),
                description.into(),
            ],
        ))
        .await
        .map_err(storage)?;
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.group.update",
            "user_group",
            Uuid::from(command.group_oid),
            &command.reason,
        )
        .await?;
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("{GROUP_SELECT} WHERE ug.id = $1"),
                [group_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(GroupEntityKind::Group))?;
        let record = group_from_row(&row)?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn group_set_enabled(
        &self,
        command: GroupStateTransaction,
        enabled: bool,
    ) -> Result<GroupRecord, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let actor_permissions =
            recheck_group_authority(&txn, &command.authority, ManagementScope::GroupsWrite).await?;
        let group_id = group_id_by_oid_locked(&txn, command.group_oid).await?;
        let current = load_group_by_id_locked(&txn, group_id).await?;
        if current.built_in {
            return Err(GroupManagementRepositoryError::BuiltInProtected);
        }
        check_version(current.version, command.expected_version)?;
        if current.enabled == enabled {
            txn.commit().await.map_err(storage)?;
            return Ok(current);
        }
        if enabled {
            let proposed = management_scopes_for_group(&txn, group_id).await?;
            ensure_delegation_subset(&actor_permissions, &proposed)?;
            let actor_oid = require_actor_user(&command.authority, ManagementScope::GroupsWrite)?;
            let permission_ids = group_permission_ids(&txn, group_id).await?;
            ensure_delegable_permission_ids(
                &txn,
                actor_oid,
                &permission_ids,
                actor_permissions.contains(&ManagementScope::PermissionDelegate),
            )
            .await?;
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE user_group SET enabled = $2, version = gen_random_uuid(), \
              updated_at = now() WHERE id = $1",
            [group_id.into(), enabled.into()],
        ))
        .await
        .map_err(storage)?;
        renew_members(&txn, group_id).await?;
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            if enabled {
                "rbac.group.enable"
            } else {
                "rbac.group.disable"
            },
            "user_group",
            Uuid::from(command.group_oid),
            &command.reason,
        )
        .await?;
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("{GROUP_SELECT} WHERE ug.id = $1"),
                [group_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(GroupEntityKind::Group))?;
        let record = group_from_row(&row)?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn group_delete(
        &self,
        command: DeleteGroupTransaction,
    ) -> Result<DeleteGroupResult, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let _actor_permissions =
            recheck_group_authority(&txn, &command.authority, ManagementScope::GroupsWrite).await?;
        let group_id = group_id_by_oid_locked(&txn, command.group_oid).await?;
        let current = load_group_by_id_locked(&txn, group_id).await?;
        if current.built_in {
            return Err(GroupManagementRepositoryError::BuiltInProtected);
        }
        check_version(current.version, command.expected_version)?;
        let member_ids = active_member_ids(&txn, group_id).await?;
        // Soft delete keeps the parent identity and every relation tombstone.
        // The stable OID and all relation OIDs remain reserved: a later group
        // is a separate definition, never revival.
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE group_membership \
                SET enabled = false, revoked_at = now(), version = gen_random_uuid(), \
                    updated_at = now() \
              WHERE group_id = $1 AND enabled = true AND revoked_at IS NULL",
            [group_id.into()],
        ))
        .await
        .map_err(storage)?;
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE group_role \
                SET enabled = false, revoked_at = now(), version = gen_random_uuid(), \
                    updated_at = now() \
              WHERE group_id = $1 AND enabled = true AND revoked_at IS NULL",
            [group_id.into()],
        ))
        .await
        .map_err(storage)?;
        let deleted = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE user_group \
                    SET enabled = false, deleted_at = now(), \
                        version = gen_random_uuid(), updated_at = now() \
                  WHERE id = $1 AND deleted_at IS NULL",
                [group_id.into()],
            ))
            .await
            .map_err(storage)?;
        if deleted.rows_affected() != 1 {
            return Err(not_found(GroupEntityKind::Group));
        }
        for user_id in member_ids {
            withdraw_user_authority_in_txn(&txn, user_id)
                .await
                .map_err(storage)?;
        }
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.group.delete",
            "user_group",
            Uuid::from(command.group_oid),
            &command.reason,
        )
        .await?;
        txn.commit().await.map_err(storage)?;
        Ok(DeleteGroupResult {
            group_oid: command.group_oid,
            deleted: true,
        })
    }

    pub(crate) async fn group_member_add(
        &self,
        command: AddGroupMemberTransaction,
    ) -> Result<GroupMembershipMutationResult, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let actor_permissions = recheck_group_authority(
            &txn,
            &command.authority,
            ManagementScope::GroupMembershipsWrite,
        )
        .await?;
        let group_id = group_id_by_oid_locked(&txn, command.group_oid).await?;
        let current = load_group_by_id_locked(&txn, group_id).await?;
        check_version(current.version, command.expected_version)?;
        if !current.enabled {
            return Err(GroupManagementRepositoryError::GroupDisabled);
        }
        let proposed = management_scopes_for_group(&txn, group_id).await?;
        ensure_delegation_subset(&actor_permissions, &proposed)?;
        let actor_oid =
            require_actor_user(&command.authority, ManagementScope::GroupMembershipsWrite)?;
        let permission_ids = group_permission_ids(&txn, group_id).await?;
        ensure_delegable_permission_ids(
            &txn,
            actor_oid,
            &permission_ids,
            actor_permissions.contains(&ManagementScope::PermissionDelegate),
        )
        .await?;
        let user_id = lock_user_id(&txn, command.user_oid).await?;
        let existing = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT 1 AS present FROM group_membership \
                 WHERE group_id = $1 AND user_id = $2 AND enabled = true \
                   AND revoked_at IS NULL FOR UPDATE",
                [group_id.into(), user_id.into()],
            ))
            .await
            .map_err(storage)?;
        if existing.is_some() {
            return Err(GroupManagementRepositoryError::MembershipAlreadyActive);
        }
        let membership_oid = GroupMembershipOid::new();
        let granted_by = match actor_user_id(&command.authority) {
            Some(actor_oid) => non_locking_user_id(&txn, actor_oid).await?,
            None => None,
        };
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO group_membership(oid, group_id, user_id, granted_by_user_id, reason, \
                enabled, version, created_at) \
             VALUES($1, $2, $3, $4, $5, true, gen_random_uuid(), now())",
            [
                Uuid::from(membership_oid).into(),
                group_id.into(),
                user_id.into(),
                Value::BigInt(granted_by),
                command.reason.clone().into(),
            ],
        ))
        .await
        .map_err(storage)?;
        let group_version = renew_group_version(&txn, group_id).await?;
        withdraw_user_authority_in_txn(&txn, user_id)
            .await
            .map_err(storage)?;
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.group.members.add",
            "group_membership",
            Uuid::from(membership_oid),
            &command.reason,
        )
        .await?;
        let membership = load_membership_by_oid(&txn, membership_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(GroupMembershipMutationResult {
            group_oid: command.group_oid,
            group_version,
            membership,
        })
    }

    pub(crate) async fn group_member_remove(
        &self,
        command: RemoveGroupMemberTransaction,
    ) -> Result<GroupMembershipMutationResult, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let _actor_permissions = recheck_group_authority(
            &txn,
            &command.authority,
            ManagementScope::GroupMembershipsWrite,
        )
        .await?;
        let group_id = group_id_by_oid_locked(&txn, command.group_oid).await?;
        let current = load_group_by_id_locked(&txn, group_id).await?;
        check_version(current.version, command.expected_version)?;
        let user_id = lock_user_id(&txn, command.user_oid).await?;
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT oid FROM group_membership WHERE group_id = $1 AND user_id = $2 \
                  AND enabled = true AND revoked_at IS NULL FOR UPDATE",
                [group_id.into(), user_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or(GroupManagementRepositoryError::MembershipNotActive)?;
        let membership_oid = GroupMembershipOid(row.try_get::<Uuid>("", "oid").map_err(storage)?);
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE group_membership SET enabled = false, revoked_at = now(), \
              version = gen_random_uuid(), updated_at = now() WHERE oid = $1",
            [Uuid::from(membership_oid).into()],
        ))
        .await
        .map_err(storage)?;
        let group_version = renew_group_version(&txn, group_id).await?;
        withdraw_user_authority_in_txn(&txn, user_id)
            .await
            .map_err(storage)?;
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.group.members.remove",
            "group_membership",
            Uuid::from(membership_oid),
            &command.reason,
        )
        .await?;
        let membership = load_membership_by_oid(&txn, membership_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(GroupMembershipMutationResult {
            group_oid: command.group_oid,
            group_version,
            membership,
        })
    }

    pub(crate) async fn group_roles_set(
        &self,
        command: SetGroupRolesTransaction,
    ) -> Result<GroupRoleMutationResult, GroupManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        lock_owner_lifecycle(&txn).await.map_err(storage)?;
        let actor_permissions =
            recheck_group_authority(&txn, &command.authority, ManagementScope::GroupRolesWrite)
                .await?;
        let group_id = group_id_by_oid_locked(&txn, command.group_oid).await?;
        let current = load_group_by_id_locked(&txn, group_id).await?;
        if current.built_in {
            return Err(GroupManagementRepositoryError::BuiltInProtected);
        }
        check_version(current.version, command.expected_version)?;
        let roles = lock_roles(&txn, &command.role_oids).await?;
        if let Some(disabled) = roles.iter().find(|role| !role.enabled) {
            return Err(GroupManagementRepositoryError::RoleDisabled {
                role_oid: disabled.oid,
            });
        }
        let current_rows = txn
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id, oid, role_id FROM group_role \
                 WHERE group_id = $1 AND enabled = true AND revoked_at IS NULL FOR UPDATE",
                [group_id.into()],
            ))
            .await
            .map_err(storage)?;
        let mut current_bindings: BTreeMap<i64, GroupRoleOid> = BTreeMap::new();
        for row in current_rows {
            current_bindings.insert(
                row.try_get::<i64>("", "role_id").map_err(storage)?,
                GroupRoleOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
            );
        }
        let proposed_ids: BTreeSet<i64> = roles.iter().map(|role| role.id).collect();
        let current_ids: BTreeSet<i64> = current_bindings.keys().copied().collect();
        let (added_ids, removed_ids) = role_binding_changes(&current_ids, &proposed_ids);
        if added_ids.is_empty() && removed_ids.is_empty() {
            txn.commit().await.map_err(storage)?;
            return Ok(GroupRoleMutationResult {
                group_oid: command.group_oid,
                group_version: current.version,
                role_oids: roles.iter().map(|role| role.oid).collect(),
                added_count: 0,
                removed_count: 0,
            });
        }
        let added_scopes = management_scopes_for_roles(&txn, &added_ids).await?;
        ensure_delegation_subset(&actor_permissions, &added_scopes)?;
        let actor_oid = require_actor_user(&command.authority, ManagementScope::GroupRolesWrite)?;
        let added_permissions = roles_permission_ids(&txn, &added_ids).await?;
        ensure_delegable_permission_ids(
            &txn,
            actor_oid,
            &added_permissions,
            actor_permissions.contains(&ManagementScope::PermissionDelegate),
        )
        .await?;
        let granted_by = match actor_user_id(&command.authority) {
            Some(actor_oid) => non_locking_user_id(&txn, actor_oid).await?,
            None => None,
        };
        for role_id in &removed_ids {
            let binding_oid = current_bindings.get(role_id).copied().ok_or_else(corrupt)?;
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE group_role SET enabled = false, revoked_at = now(), \
                  version = gen_random_uuid(), updated_at = now() WHERE oid = $1",
                [Uuid::from(binding_oid).into()],
            ))
            .await
            .map_err(storage)?;
        }
        for role in roles.iter().filter(|role| added_ids.contains(&role.id)) {
            let binding_oid = GroupRoleOid::new();
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO group_role(oid, group_id, role_id, granted_by_user_id, \
                    reason, enabled, version, created_at) \
                 VALUES($1, $2, $3, $4, $5, true, gen_random_uuid(), now())",
                [
                    Uuid::from(binding_oid).into(),
                    group_id.into(),
                    role.id.into(),
                    Value::BigInt(granted_by),
                    command.reason.clone().into(),
                ],
            ))
            .await
            .map_err(storage)?;
        }
        let group_version = renew_group_version(&txn, group_id).await?;
        renew_members(&txn, group_id).await?;
        ensure_recovery(&txn).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.group.roles.set",
            "user_group",
            Uuid::from(command.group_oid),
            &command.reason,
        )
        .await?;
        txn.commit().await.map_err(storage)?;
        Ok(GroupRoleMutationResult {
            group_oid: command.group_oid,
            group_version,
            role_oids: roles.iter().map(|role| role.oid).collect(),
            added_count: u32::try_from(added_ids.len()).unwrap_or(u32::MAX),
            removed_count: u32::try_from(removed_ids.len()).unwrap_or(u32::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use identity_application::rbac::GroupManagementRepositoryError;
    use sea_orm::DbErr;

    use super::{RECOVERY_PROTECTED_MESSAGE, map_recovery_error, role_binding_changes};

    #[test]
    fn identical_role_sets_are_a_noop() {
        let current: BTreeSet<i64> = [1, 2, 3].into_iter().collect();
        let proposed = current.clone();
        let (added, removed) = role_binding_changes(&current, &proposed);
        assert!(added.is_empty());
        assert!(removed.is_empty());

        let proposed: BTreeSet<i64> = [2, 3, 4].into_iter().collect();
        let (added, removed) = role_binding_changes(&current, &proposed);
        assert_eq!(added, vec![4]);
        assert_eq!(removed, vec![1]);
    }

    #[test]
    fn only_the_recovery_signal_maps_to_last_recovery_protection() {
        assert!(matches!(
            map_recovery_error(DbErr::Custom(RECOVERY_PROTECTED_MESSAGE.to_owned())),
            GroupManagementRepositoryError::LastRecoveryProtected
        ));
        assert!(matches!(
            map_recovery_error(DbErr::Custom("connection reset".to_owned())),
            GroupManagementRepositoryError::Storage(_)
        ));
    }
}
