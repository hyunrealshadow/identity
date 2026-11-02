//! Canonical scope catalog persistence.
//!
//! A scope row is the single definition shared by roles, clients, consent,
//! token issuance and resource projections. API scopes own `resource_id`;
//! protocol/identity scopes leave it `NULL`.

use identity_application::rbac::{
    CreateScopeTransaction, RbacEntityKind, RbacManagementRepositoryError, RbacPageData,
    RbacProtectedKind, ScopeOid, ScopePageEntry, ScopeQuery, ScopeRecord, ScopeStateTransaction,
    UpdateScopeTransaction,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{
    authorization::ManagementScope,
    rbac::{LocalizedMetadata, ResourceOid},
};
use sea_orm::TransactionTrait;
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::super::localized;
use super::{
    RbacManagementRepositoryImpl,
    audit::append_semantic_audit,
    authority::recheck_authority,
    support::{
        Binds, CursorComparison, corrupt, escape_like, keyset_condition, not_found,
        order_is_descending, page_flags, parse_localized_metadata, scope_descriptions, storage,
        utc, withdraw_users_affected_by_scope,
    },
};

const SCOPE_SELECT: &str = "SELECT s.id, s.oid, s.resource_id, s.code, s.name, s.names, \
            s.description, s.descriptions, s.built_in, s.enabled, s.version, \
            s.created_at, s.updated_at FROM \"scope\" s";

pub(crate) fn scope_from_row(
    row: &sea_orm::QueryResult,
) -> Result<ScopeRecord, RbacManagementRepositoryError> {
    let metadata = parse_localized_metadata(
        row.try_get::<serde_json::Value>("", "names")
            .map_err(storage)?,
        row.try_get::<serde_json::Value>("", "descriptions")
            .map_err(storage)?,
    )?;
    Ok(ScopeRecord {
        oid: ScopeOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        resource_oid: row
            .try_get::<Option<Uuid>>("", "resource_id")
            .map_err(storage)?
            .map(ResourceOid),
        code: row.try_get::<String>("", "code").map_err(storage)?,
        name: row.try_get::<String>("", "name").map_err(storage)?,
        names: scope_descriptions(&metadata.names),
        description: row.try_get::<String>("", "description").map_err(storage)?,
        descriptions: scope_descriptions(&metadata.descriptions),
        built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
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

async fn load_scope_unlocked(
    txn: &DatabaseTransaction,
    oid: ScopeOid,
) -> Result<ScopeRecord, RbacManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{SCOPE_SELECT} WHERE s.oid = $1"),
            [oid.0.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(RbacEntityKind::Scope))?;
    scope_from_row(&row)
}

async fn load_scope_locked(
    txn: &DatabaseTransaction,
    oid: ScopeOid,
) -> Result<ScopeRecord, RbacManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{SCOPE_SELECT} WHERE s.oid = $1 FOR UPDATE"),
            [oid.0.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(RbacEntityKind::Scope))?;
    scope_from_row(&row)
}

fn scope_metadata(
    names: Vec<identity_application::rbac::ScopeDescription>,
    descriptions: Vec<identity_application::rbac::ScopeDescription>,
) -> Result<LocalizedMetadata, RbacManagementRepositoryError> {
    let names = names
        .into_iter()
        .map(|entry| identity_domain::rbac::LocalizedText::new(entry.locale, entry.value))
        .collect();
    let descriptions = descriptions
        .into_iter()
        .map(|entry| identity_domain::rbac::LocalizedText::new(entry.locale, entry.value))
        .collect();
    LocalizedMetadata::canonicalize(names, descriptions).map_err(|_| corrupt())
}

fn scope_filter_conditions(
    filter: &identity_application::rbac::ScopeFilter,
    binds: &mut Binds,
) -> Vec<String> {
    let mut conditions = vec!["1=1".to_owned()];
    if let Some(term) = &filter.query {
        let pattern = format!("%{}%", escape_like(term));
        conditions.push(format!("s.code ILIKE {}", binds.push(pattern)));
    }
    if let Some(built_in) = filter.built_in {
        conditions.push(format!("s.built_in = {}", binds.push(built_in)));
    }
    if let Some(enabled) = filter.enabled {
        conditions.push(format!("s.enabled = {}", binds.push(enabled)));
    }
    if filter.api_only {
        // Console pickers show only concrete resource API permissions, not
        // protocol scopes or wildcard selector definitions.
        conditions.push("s.resource_id IS NOT NULL AND position('*' in s.code) = 0".to_owned());
    }
    if let Some(resource_oid) = filter.resource_oid {
        conditions.push(format!(
            "s.resource_id = {}",
            binds.push(Uuid::from(resource_oid))
        ));
    }
    if let Some(role_oid) = filter.role_oid {
        let role_placeholder = binds.push(Uuid::from(role_oid));
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM role_permission membership \
                  JOIN \"role\" role_row ON role_row.id = membership.role_id \
                  WHERE role_row.oid = {role_placeholder} AND membership.scope_id = s.id)"
        ));
    }
    conditions
}

impl RbacManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "scope.count"))]
    pub(crate) async fn scope_count(
        &self,
        filter: identity_application::rbac::ScopeFilter,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let mut binds = Binds::new();
        let conditions = scope_filter_conditions(&filter, &mut binds);
        let sql = format!(
            "SELECT count(*)::bigint AS total_count FROM scope s WHERE {}",
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

    pub(crate) async fn scope_find(
        &self,
        oid: ScopeOid,
    ) -> Result<Option<ScopeRecord>, RbacManagementRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("{SCOPE_SELECT} WHERE s.oid = $1"),
                [oid.0.into()],
            ))
            .await
            .map_err(storage)?;
        row.as_ref().map(scope_from_row).transpose()
    }

    pub(crate) async fn scope_list(
        &self,
        query: ScopeQuery,
    ) -> Result<RbacPageData<ScopePageEntry>, RbacManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let column = match query.order {
            identity_application::rbac::ScopeOrder::CreatedAtAsc
            | identity_application::rbac::ScopeOrder::CreatedAtDesc => "s.created_at",
            identity_application::rbac::ScopeOrder::CodeAsc
            | identity_application::rbac::ScopeOrder::CodeDesc => "s.code",
        };
        let mut binds = Binds::new();
        let mut conditions = scope_filter_conditions(&query.filter, &mut binds);
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                column,
                "s.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                column,
                "s.id",
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
            "{SCOPE_SELECT} WHERE {where_sql} \
             ORDER BY {column} {direction_sql}, s.id {direction_sql} LIMIT {limit_placeholder}"
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
            let record = scope_from_row(&row)?;
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let tie = RbacTie::Id(id);
            let sort_key = match query.order {
                identity_application::rbac::ScopeOrder::CreatedAtAsc
                | identity_application::rbac::ScopeOrder::CreatedAtDesc => RbacSortKey::CreatedAt {
                    created_at: record.created_at,
                    tie,
                },
                identity_application::rbac::ScopeOrder::CodeAsc
                | identity_application::rbac::ScopeOrder::CodeDesc => RbacSortKey::Text {
                    value: record.code.clone(),
                    tie,
                },
            };
            items.push(ScopePageEntry { sort_key, record });
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

    pub(crate) async fn scope_create(
        &self,
        command: CreateScopeTransaction,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::ScopesWrite, None).await?;
        let code =
            identity_domain::rbac::PermissionCode::parse(command.code.as_str()).map_err(|_| {
                RbacManagementRepositoryError::InvalidPermissionCode {
                    code: command.code.clone(),
                }
            })?;
        let code = code.as_str().to_owned();
        identity_domain::rbac::validate_business_scope_reference(&code).map_err(|_| {
            RbacManagementRepositoryError::ScopeNotBusiness {
                scope: code.clone(),
            }
        })?;
        let resource_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT oid FROM resource WHERE oid = $1 FOR UPDATE",
                [Uuid::from(command.resource_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
        let _ = resource_row;
        let metadata = scope_metadata(command.names, command.descriptions)?;
        let (names, descriptions) = localized::encode_metadata(&metadata);
        let name = command.name;
        let description = command.description;
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO \"scope\"(oid, resource_id, code, name, names, description, \
                    descriptions, built_in, enabled, version, created_at) \
                 VALUES($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, false, true, \
                    gen_random_uuid(), now()) \
                 ON CONFLICT DO NOTHING RETURNING oid",
                [
                    command.scope_oid.0.into(),
                    Uuid::from(command.resource_oid).into(),
                    code.into(),
                    name.into(),
                    names.to_string().into(),
                    description.into(),
                    descriptions.to_string().into(),
                ],
            ))
            .await
            .map_err(storage)?;
        if row.is_none() {
            return Err(RbacManagementRepositoryError::Duplicate(
                identity_application::rbac::RbacDuplicateKind::ScopeCode,
            ));
        }
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.scope.create",
            "scope",
            command.scope_oid.0,
            &command.reason,
        )
        .await?;
        let record = load_scope_unlocked(&txn, command.scope_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn scope_update(
        &self,
        command: UpdateScopeTransaction,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::ScopesWrite, None).await?;
        let current = load_scope_locked(&txn, command.scope_oid).await?;
        if current.built_in {
            return Err(RbacManagementRepositoryError::Protected(
                RbacProtectedKind::BuiltInScope,
            ));
        }
        if current.version != command.expected_version {
            return Err(RbacManagementRepositoryError::VersionConflict {
                current_version: current.version,
            });
        }
        if command.name.is_none()
            && command.names.is_none()
            && command.description.is_none()
            && command.descriptions.is_none()
        {
            return Err(RbacManagementRepositoryError::EmptyUpdate);
        }
        let metadata = scope_metadata(
            command.names.unwrap_or_else(|| current.names.clone()),
            command
                .descriptions
                .unwrap_or_else(|| current.descriptions.clone()),
        )?;
        let (names, descriptions) = localized::encode_metadata(&metadata);
        let name = command.name.unwrap_or(current.name);
        let description = command.description.unwrap_or(current.description);
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"scope\" SET name = $2, names = $3::jsonb, description = $4, \
              descriptions = $5::jsonb, version = gen_random_uuid(), updated_at = now() \
              WHERE oid = $1",
            [
                command.scope_oid.0.into(),
                name.into(),
                names.to_string().into(),
                description.into(),
                descriptions.to_string().into(),
            ],
        ))
        .await
        .map_err(storage)?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.scope.update",
            "scope",
            command.scope_oid.0,
            &command.reason,
        )
        .await?;
        let record = load_scope_unlocked(&txn, command.scope_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn scope_set_enabled(
        &self,
        command: ScopeStateTransaction,
        enabled: bool,
    ) -> Result<ScopeRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &command.authority, ManagementScope::ScopesWrite, None).await?;
        let current = load_scope_locked(&txn, command.scope_oid).await?;
        if current.built_in {
            return Err(RbacManagementRepositoryError::Protected(
                RbacProtectedKind::BuiltInScope,
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
        let scope_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM \"scope\" WHERE oid = $1",
                [command.scope_oid.0.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Scope))?;
        let scope_id = scope_row.try_get::<i64>("", "id").map_err(storage)?;
        if enabled {
            super::delegation::ensure_delegable_permissions(
                &txn,
                &command.authority,
                &std::collections::BTreeSet::from([scope_id]),
            )
            .await?;
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"scope\" SET enabled = $2, version = gen_random_uuid(), \
              updated_at = now() WHERE oid = $1",
            [command.scope_oid.0.into(), enabled.into()],
        ))
        .await
        .map_err(storage)?;
        withdraw_users_affected_by_scope(&txn, scope_id).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            if enabled {
                "rbac.scope.enable"
            } else {
                "rbac.scope.disable"
            },
            "scope",
            command.scope_oid.0,
            &command.reason,
        )
        .await?;
        let record = load_scope_unlocked(&txn, command.scope_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }
}
