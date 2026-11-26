//! Assigning and revoking user roles under the delegation and recovery guards.

use super::*;

impl RbacManagementRepositoryImpl {
    pub(crate) async fn user_role_assign(
        &self,
        command: AssignUserRolesTransaction,
    ) -> Result<UserRoleMutationResult, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::RoleAssignmentsWrite,
            Some(command.user_oid),
        )
        .await?;
        let user_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id, version FROM \"user\" WHERE oid = $1 FOR UPDATE",
                [Uuid::from(command.user_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::User))?;
        let user_id = user_row.try_get::<i64>("", "id").map_err(storage)?;
        let current = user_row.try_get::<Uuid>("", "version").map_err(storage)?;
        if current != command.expected_user_version {
            return Err(RbacManagementRepositoryError::UserVersionStale {
                current_version: current,
            });
        }
        let roles = lock_roles(&txn, &command.role_oids).await?;
        if let Some(disabled) = roles.iter().find(|role| !role.enabled) {
            return Err(RbacManagementRepositoryError::RoleDisabled {
                role_oid: disabled.oid,
            });
        }
        let mut existing: BTreeMap<i64, UserRoleOid> = BTreeMap::new();
        if !roles.is_empty() {
            let mut binds = Binds::new();
            let user_placeholder = binds.push(user_id);
            let placeholders = roles
                .iter()
                .map(|role| binds.push(role.id))
                .collect::<Vec<_>>()
                .join(", ");
            let rows = txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    format!(
                        "SELECT oid, role_id FROM user_role \
                         WHERE user_id = {user_placeholder} AND enabled = true \
                           AND revoked_at IS NULL AND role_id IN ({placeholders}) FOR UPDATE"
                    ),
                    binds.into_values(),
                ))
                .await
                .map_err(storage)?;
            for row in rows {
                existing.insert(
                    row.try_get::<i64>("", "role_id").map_err(storage)?,
                    UserRoleOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
                );
            }
        }
        // Delegation ceiling is evaluated against the actor's authority before
        // this transaction adds any binding.
        if roles.iter().any(|role| !existing.contains_key(&role.id)) {
            let mut added_ids = BTreeSet::new();
            let mut binds = Binds::new();
            let placeholders = roles
                .iter()
                .filter(|role| !existing.contains_key(&role.id))
                .map(|role| binds.push(role.id))
                .collect::<Vec<_>>()
                .join(", ");
            let rows = txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    format!(
                        "SELECT scope_id FROM role_permission WHERE role_id IN ({placeholders})"
                    ),
                    binds.into_values(),
                ))
                .await
                .map_err(storage)?;
            for row in rows {
                added_ids.insert(row.try_get::<i64>("", "scope_id").map_err(storage)?);
            }
            delegation::ensure_delegable_permissions(&txn, &command.authority, &added_ids).await?;
        }
        let actor_user_id = match &command.authority.actor.principal {
            ActorPrincipal::User { user_oid, .. } => user_id_by_oid(&txn, *user_oid).await?,
            ActorPrincipal::Client { .. } => None,
        };
        let mut created = Vec::new();
        let mut user_role_oids = Vec::with_capacity(roles.len());
        for role in &roles {
            if let Some(user_role_oid) = existing.get(&role.id) {
                user_role_oids.push(*user_role_oid);
                continue;
            }
            let user_role_oid = UserRoleOid::new();
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO user_role(oid, user_id, role_id, granted_by_user_id, reason, \
                    enabled, version, created_at) \
                 VALUES($1, $2, $3, $4, $5, true, gen_random_uuid(), now())",
                [
                    Uuid::from(user_role_oid).into(),
                    user_id.into(),
                    role.id.into(),
                    Value::BigInt(actor_user_id),
                    command.reason.clone().into(),
                ],
            ))
            .await
            .map_err(storage)?;
            created.push((user_role_oid, role.audit_ref()));
            user_role_oids.push(user_role_oid);
        }
        let version = if created.is_empty() {
            current
        } else {
            // A real direct-grant change rotates the CAS token and permanently
            // withdraws every existing subject credential.
            authorization_lifecycle::withdraw_user_authority_in_txn(&txn, user_id)
                .await
                .map_err(storage)?
                .as_uuid()
        };
        let granted: Vec<AuditRef> = created.iter().map(|(_, role)| role.clone()).collect();
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserRoleGrant, Uuid::from(command.user_oid))
                .with_changes(|changes| {
                    changes.delta(AuditField::Roles, &granted, &[]);
                }),
        )
        .await?;
        txn.commit().await.map_err(storage)?;
        Ok(UserRoleMutationResult {
            user_oid: command.user_oid,
            user_version: version,
            user_role_oids,
            created_count: created.len() as u32,
            revoked_count: 0,
        })
    }

    pub(crate) async fn user_role_revoke(
        &self,
        command: RevokeUserRolesTransaction,
    ) -> Result<UserRoleMutationResult, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::RoleAssignmentsWrite,
            Some(command.user_oid),
        )
        .await?;
        let user_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id, version FROM \"user\" WHERE oid = $1 FOR UPDATE",
                [Uuid::from(command.user_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::User))?;
        let user_id = user_row.try_get::<i64>("", "id").map_err(storage)?;
        let current = user_row.try_get::<Uuid>("", "version").map_err(storage)?;
        if current != command.expected_user_version {
            return Err(RbacManagementRepositoryError::UserVersionStale {
                current_version: current,
            });
        }
        let roles = lock_roles(&txn, &command.role_oids).await?;
        let mut user_role_oids = Vec::with_capacity(roles.len());
        for role in &roles {
            let row = txn
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT oid FROM user_role \
                     WHERE user_id = $1 AND role_id = $2 AND enabled = true \
                       AND revoked_at IS NULL FOR UPDATE",
                    [user_id.into(), role.id.into()],
                ))
                .await
                .map_err(storage)?;
            let Some(row) = row else {
                return Err(RbacManagementRepositoryError::RoleNotAssigned { role_oid: role.oid });
            };
            let user_role_oid = UserRoleOid(row.try_get::<Uuid>("", "oid").map_err(storage)?);
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE user_role SET enabled = false, revoked_at = now(), \
                  version = gen_random_uuid(), updated_at = now() \
                 WHERE oid = $1",
                [Uuid::from(user_role_oid).into()],
            ))
            .await
            .map_err(storage)?;
            user_role_oids.push(user_role_oid);
        }
        let version = if user_role_oids.is_empty() {
            current
        } else {
            // Revoking a direct grant is a permanent boundary: running CAS plus
            // durable withdrawal prevents a remove/re-add cycle from reviving
            // old codes, refresh tokens or access tokens.
            authorization_lifecycle::withdraw_user_authority_in_txn(&txn, user_id)
                .await
                .map_err(storage)?
                .as_uuid()
        };
        let revoked: Vec<AuditRef> = roles.iter().map(LockedRole::audit_ref).collect();
        append_semantic_audit(
            &txn,
            &command.authority,
            AuditRecord::success(AuditAction::UserRoleRevoke, Uuid::from(command.user_oid))
                .with_changes(|changes| {
                    changes.delta(AuditField::Roles, &[], &revoked);
                }),
        )
        .await?;
        txn.commit().await.map_err(storage)?;
        Ok(UserRoleMutationResult {
            user_oid: command.user_oid,
            user_version: version,
            user_role_oids,
            created_count: 0,
            revoked_count: roles.len() as u32,
        })
    }
}
