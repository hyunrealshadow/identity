//! Role persistence and explicit role-permission membership.

use std::collections::BTreeSet;

use identity_application::rbac::{
    CreateRoleTransaction, RbacEntityKind, RbacManagementRepositoryError, RbacPageData,
    RbacProtectedKind, RoleFilter, RoleOrder, RolePageEntry, RoleQuery, RoleRecord,
    RoleStateTransaction, SetRolePermissionsTransaction, UpdateRoleTransaction,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{
    authorization::ManagementScope,
    rbac::{LocalizedMetadata, RoleOid, RolePermissionOid},
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement, TransactionTrait};
use uuid::Uuid;

use super::{
    super::authorization_lifecycle,
    RbacManagementRepositoryImpl,
    audit::append_semantic_audit,
    authority::recheck_authority,
    delegation,
    support::{
        Binds, CursorComparison, corrupt, escape_like, keyset_condition, metadata_json, not_found,
        order_is_descending, page_flags, parse_localized_metadata, storage, utc,
    },
};

const ROLE_SELECT: &str = "SELECT r.id, r.oid, r.name, r.description, r.built_in, \
            r.names, r.descriptions, r.enabled, r.version, \
            r.created_at, r.updated_at FROM \"role\" r";

fn role_from_row(row: &sea_orm::QueryResult) -> Result<RoleRecord, RbacManagementRepositoryError> {
    let metadata = parse_localized_metadata(
        row.try_get::<serde_json::Value>("", "names")
            .map_err(storage)?,
        row.try_get::<serde_json::Value>("", "descriptions")
            .map_err(storage)?,
    )?;
    Ok(RoleRecord {
        oid: RoleOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        name: row.try_get::<String>("", "name").map_err(storage)?,
        description: row.try_get::<String>("", "description").map_err(storage)?,
        built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
        names: metadata.names,
        descriptions: metadata.descriptions,
        enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        version: row.try_get::<Uuid>("", "version").map_err(storage)?,
        created_at: utc(row
            .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "created_at")
            .map_err(storage)?),
        updated_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
            .map_err(storage)?
            .map(utc),
    })
}

async fn load_role(
    txn: &DatabaseTransaction,
    oid: RoleOid,
    lock: bool,
) -> Result<RoleRecord, RbacManagementRepositoryError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{ROLE_SELECT} WHERE r.oid = $1{suffix}"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(RbacEntityKind::Role))?;
    role_from_row(&row)
}

/// Permanently withdraw every user whose effective authority includes this
/// role, both through a direct binding and through an active group path.
/// Callers already hold the unified authorization lifecycle lock. This rotates
/// each user CAS token and tombstones every already-issued subject artifact,
/// including consumed single-use parents.
async fn renew_users_affected_by_role(
    txn: &DatabaseTransaction,
    role_id: i64,
) -> Result<(), RbacManagementRepositoryError> {
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT user_id FROM (
    SELECT binding.user_id
    FROM user_role_binding binding
    WHERE binding.role_id = $1
      AND binding.enabled = true
      AND binding.revoked_at IS NULL
    UNION
    SELECT membership.user_id
    FROM group_role_binding relation
    JOIN group_membership membership ON membership.group_id = relation.group_id
    WHERE relation.role_id = $1
      AND relation.enabled = true
      AND relation.revoked_at IS NULL
      AND membership.enabled = true
      AND membership.revoked_at IS NULL
) affected
ORDER BY user_id
"#,
            [role_id.into()],
        ))
        .await
        .map_err(storage)?;
    for row in rows {
        let user_id = row.try_get::<i64>("", "user_id").map_err(storage)?;
        authorization_lifecycle::withdraw_user_authority_in_txn(txn, user_id)
            .await
            .map_err(storage)?;
    }
    Ok(())
}

fn role_filter_conditions(filter: &RoleFilter, binds: &mut Binds) -> Vec<String> {
    let mut conditions = vec!["1=1".to_owned()];
    if let Some(term) = &filter.query {
        let pattern = format!("%{}%", escape_like(term));
        let placeholder = binds.push(pattern);
        conditions.push(format!(
            "(r.name ILIKE {placeholder} OR r.description ILIKE {placeholder} \
             OR EXISTS (SELECT 1 FROM jsonb_each_text(r.names) AS n WHERE n.value ILIKE {placeholder}) \
             OR EXISTS (SELECT 1 FROM jsonb_each_text(r.descriptions) AS d WHERE d.value ILIKE {placeholder}))"
        ));
    }
    if let Some(enabled) = filter.enabled {
        conditions.push(format!("r.enabled = {}", binds.push(enabled)));
    }
    if let Some(built_in) = filter.built_in {
        conditions.push(format!("r.built_in = {}", binds.push(built_in)));
    }
    if let Some(scope_oid) = filter.scope_oid {
        // This predicate is part of the WHERE clause, so role membership is
        // filtered before keyset pagination and LIMIT. It does not load and
        // discard an unfiltered page in memory.
        let scope_placeholder = binds.push(scope_oid.0);
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM role_permission rp \
             WHERE rp.scope_id = (SELECT current_scope.id \
                                  FROM \"scope\" current_scope \
                                  WHERE current_scope.oid = {scope_placeholder}) \
               AND rp.role_id = r.id)"
        ));
    }
    conditions
}

impl RbacManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "role.count"))]
    pub(crate) async fn role_count(
        &self,
        filter: RoleFilter,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let mut binds = Binds::new();
        let conditions = role_filter_conditions(&filter, &mut binds);
        let sql = format!(
            "SELECT count(*)::bigint AS total_count FROM \"role\" r WHERE {}",
            conditions.join(" AND ")
        );
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                binds.into_values(),
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let value = row.try_get::<i64>("", "total_count").map_err(storage)?;
        u64::try_from(value).map_err(|_| corrupt())
    }

    pub(crate) async fn role_find(
        &self,
        oid: RoleOid,
    ) -> Result<Option<RoleRecord>, RbacManagementRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("{ROLE_SELECT} WHERE r.oid = $1"),
                [Uuid::from(oid).into()],
            ))
            .await
            .map_err(storage)?;
        row.as_ref().map(role_from_row).transpose()
    }

    pub(crate) async fn role_list(
        &self,
        query: RoleQuery,
    ) -> Result<RbacPageData<RolePageEntry>, RbacManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let column = match query.order {
            RoleOrder::CreatedAtAsc | RoleOrder::CreatedAtDesc => "r.created_at",
            RoleOrder::NameAsc | RoleOrder::NameDesc => "r.name",
        };
        let mut binds = Binds::new();
        let mut conditions = role_filter_conditions(&query.filter, &mut binds);
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                column,
                "r.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                column,
                "r.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push((query.limit + 1) as i64);
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "{ROLE_SELECT} WHERE {where_sql} \
             ORDER BY {column} {direction_sql}, r.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                binds.into_values(),
            ))
            .await
            .map_err(storage)?;
        let has_more = rows.len() > query.limit;
        let mut rows = rows;
        rows.truncate(query.limit);
        if query.direction == RbacPageDirection::Backward {
            rows.reverse();
        }
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let record = role_from_row(&row)?;
            let tie = RbacTie::Id(id);
            let sort_key = match query.order {
                RoleOrder::CreatedAtAsc | RoleOrder::CreatedAtDesc => RbacSortKey::CreatedAt {
                    created_at: record.created_at,
                    tie,
                },
                RoleOrder::NameAsc | RoleOrder::NameDesc => RbacSortKey::Text {
                    value: record.name.clone(),
                    tie,
                },
            };
            items.push(RolePageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        Ok(RbacPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }

    pub(crate) async fn role_create(
        &self,
        command: CreateRoleTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::RolesWrite, None).await?;
        let (names, descriptions) = metadata_json(&command.metadata);
        let name = command.name;
        let description = command.description;
        txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO \"role\"(oid, name, description, built_in, \
                names, descriptions, enabled, version, created_at) \
             VALUES($1, $2, $3, false, $4::jsonb, $5::jsonb, true, \
                gen_random_uuid(), now()) RETURNING id",
            [
                Uuid::from(command.role_oid).into(),
                name.into(),
                description.into(),
                names.to_string().into(),
                descriptions.to_string().into(),
            ],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.role.create",
            "role",
            Uuid::from(command.role_oid),
            &command.reason,
        )
        .await?;
        let record = load_role(&txn, command.role_oid, false).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn role_update(
        &self,
        command: UpdateRoleTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::RolesWrite, None).await?;
        let current = load_role(&txn, command.role_oid, true).await?;
        if current.built_in {
            return Err(RbacManagementRepositoryError::Protected(
                RbacProtectedKind::BuiltInRole,
            ));
        }
        if current.version != command.expected_version {
            return Err(RbacManagementRepositoryError::VersionConflict {
                current_version: current.version,
            });
        }
        if command.name.is_none()
            && command.description.is_none()
            && command.names.is_none()
            && command.descriptions.is_none()
        {
            return Err(RbacManagementRepositoryError::EmptyUpdate);
        }
        let current_metadata = current.metadata();
        // Independent partial patches: the locked current row supplies every
        // omitted field. An explicit empty descriptions list is preserved as
        // "clear"; an omitted names field preserves the current translations.
        let metadata = LocalizedMetadata::canonicalize(
            command
                .names
                .unwrap_or_else(|| current_metadata.names.clone()),
            command
                .descriptions
                .unwrap_or_else(|| current_metadata.descriptions.clone()),
        )
        .map_err(|_| corrupt())?;
        let name = command.name.unwrap_or(current.name);
        let description = command.description.unwrap_or(current.description);
        let (names, descriptions) = metadata_json(&metadata);
        // Display edits advance the row's UUID change token. They do not fan
        // out user authority: only enable/disable and membership changes do.
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"role\" SET name = $2, description = $3, \
              names = $4::jsonb, descriptions = $5::jsonb, \
              version = gen_random_uuid(), updated_at = now() WHERE oid = $1",
            [
                Uuid::from(command.role_oid).into(),
                name.into(),
                description.into(),
                names.to_string().into(),
                descriptions.to_string().into(),
            ],
        ))
        .await
        .map_err(storage)?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.role.update",
            "role",
            Uuid::from(command.role_oid),
            &command.reason,
        )
        .await?;
        let record = load_role(&txn, command.role_oid, false).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn role_set_enabled(
        &self,
        command: RoleStateTransaction,
        enabled: bool,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::RolesWrite, None).await?;
        let current = load_role(&txn, command.role_oid, true).await?;
        if current.built_in {
            return Err(RbacManagementRepositoryError::Protected(
                RbacProtectedKind::BuiltInRole,
            ));
        }
        if current.version != command.expected_version {
            return Err(RbacManagementRepositoryError::VersionConflict {
                current_version: current.version,
            });
        }
        if current.enabled == enabled {
            txn.commit().await.map_err(storage)?;
            return Ok(current);
        }
        let role_id = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM \"role\" WHERE oid = $1",
                [Uuid::from(command.role_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Role))?
            .try_get::<i64>("", "id")
            .map_err(storage)?;
        if enabled {
            let rows = txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT scope_id FROM role_permission WHERE role_id = $1",
                    [role_id.into()],
                ))
                .await
                .map_err(storage)?;
            let mut scopes = BTreeSet::new();
            for row in rows {
                scopes.insert(row.try_get::<i64>("", "scope_id").map_err(storage)?);
            }
            delegation::ensure_delegable_permissions(&txn, &command.authority, &scopes).await?;
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"role\" SET enabled = $2, version = gen_random_uuid(), \
              updated_at = now() WHERE oid = $1",
            [Uuid::from(command.role_oid).into(), enabled.into()],
        ))
        .await
        .map_err(storage)?;
        renew_users_affected_by_role(&txn, role_id).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            if enabled {
                "rbac.role.enable"
            } else {
                "rbac.role.disable"
            },
            "role",
            Uuid::from(command.role_oid),
            &command.reason,
        )
        .await?;
        let record = load_role(&txn, command.role_oid, false).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn role_set_permissions(
        &self,
        command: SetRolePermissionsTransaction,
    ) -> Result<RoleRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::RolesWrite, None).await?;
        let current = load_role(&txn, command.role_oid, true).await?;
        if current.built_in {
            return Err(RbacManagementRepositoryError::Protected(
                RbacProtectedKind::BuiltInRole,
            ));
        }
        if current.version != command.expected_version {
            return Err(RbacManagementRepositoryError::VersionConflict {
                current_version: current.version,
            });
        }
        let role_id = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM \"role\" WHERE oid = $1",
                [Uuid::from(command.role_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Role))?
            .try_get::<i64>("", "id")
            .map_err(storage)?;
        let mut requested_ids = BTreeSet::new();
        if !command.scope_oids.is_empty() {
            let mut binds = Binds::new();
            let placeholders = command
                .scope_oids
                .iter()
                .map(|oid| binds.push(oid.0))
                .collect::<Vec<_>>()
                .join(", ");
            let rows = txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    format!(
                        "SELECT id, resource_id, code FROM \"scope\" \
                         WHERE oid IN ({placeholders})"
                    ),
                    binds.into_values(),
                ))
                .await
                .map_err(storage)?;
            if rows.len() != command.scope_oids.len() {
                return Err(not_found(RbacEntityKind::Scope));
            }
            for row in rows {
                let resource_id = row
                    .try_get::<Option<Uuid>>("", "resource_id")
                    .map_err(storage)?;
                let code = row.try_get::<String>("", "code").map_err(storage)?;
                // Role grants are concrete API-scope memberships. Protocol
                // scopes have no resource and selectors would smuggle future
                // codes; both are rejected before the replacement write.
                if resource_id.is_none() || code.contains('*') {
                    return Err(RbacManagementRepositoryError::ScopeNotBusiness { scope: code });
                }
                requested_ids.insert(row.try_get::<i64>("", "id").map_err(storage)?);
            }
        }
        delegation::validate_built_in_permission_references(&txn, &command.scope_oids).await?;
        let current_rows = txn
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT scope_id FROM role_permission WHERE role_id = $1",
                [role_id.into()],
            ))
            .await
            .map_err(storage)?;
        let current_ids = current_rows
            .into_iter()
            .filter_map(|row| row.try_get::<i64>("", "scope_id").ok())
            .collect::<BTreeSet<_>>();
        if current_ids == requested_ids {
            txn.commit().await.map_err(storage)?;
            return Ok(current);
        }
        let added: BTreeSet<i64> = requested_ids.difference(&current_ids).copied().collect();
        delegation::ensure_delegable_permissions(&txn, &command.authority, &added).await?;
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM role_permission WHERE role_id = $1",
            [role_id.into()],
        ))
        .await
        .map_err(storage)?;
        for scope_id in &requested_ids {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO role_permission(oid, role_id, scope_id, created_at) \
                 VALUES($1, $2, $3, now())",
                [
                    Uuid::from(RolePermissionOid::new()).into(),
                    role_id.into(),
                    (*scope_id).into(),
                ],
            ))
            .await
            .map_err(storage)?;
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"role\" SET version = gen_random_uuid(), \
              updated_at = now() WHERE id = $1",
            [role_id.into()],
        ))
        .await
        .map_err(storage)?;
        renew_users_affected_by_role(&txn, role_id).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.role.permissions.set",
            "role",
            Uuid::from(command.role_oid),
            &command.reason,
        )
        .await?;
        let record = load_role(&txn, command.role_oid, false).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }
}
