//! API resource persistence for unified RBAC management.
//!
//! A resource is an authorization boundary only. It stores no accepted-scope
//! JSON and no separate policy row; owned scope rows are the single catalog.

use identity_application::rbac::{
    ApiResourceRecord, CreateResourceTransaction, RbacEntityKind, RbacManagementRepositoryError,
    RbacPageData, ResourcePageEntry, ResourceQuery, ResourceStateTransaction,
    UpdateResourceTransaction,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{
    authorization::ManagementScope, openid_connect::API_RESOURCE, rbac::ResourceOid,
};
use sea_orm::TransactionTrait;
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::super::oauth_resource::withdraw_resource_authorization_artifacts;
use super::{
    RbacManagementRepositoryImpl,
    audit::append_semantic_audit,
    authority::recheck_authority,
    support::{
        Binds, CursorComparison, escape_like, keyset_condition, not_found, order_is_descending,
        page_flags, parse_scope_names, storage, utc, withdraw_users_affected_by_resource,
    },
};

const RESOURCE_SELECT: &str = "SELECT r.oid, r.uri, r.name, r.enabled, r.version, \
            r.created_at, r.updated_at, \
            COALESCE((SELECT jsonb_agg(s.code ORDER BY s.code) FROM \"scope\" s \
                      WHERE s.resource_id = r.oid), '[]'::jsonb) AS accepted_scopes \
     FROM resource r";

fn resource_from_row(
    row: &sea_orm::QueryResult,
) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
    Ok(ApiResourceRecord {
        oid: ResourceOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        uri: row.try_get::<String>("", "uri").map_err(storage)?,
        name: row.try_get::<String>("", "name").map_err(storage)?,
        enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        accepted_scopes: parse_scope_names(
            row.try_get::<serde_json::Value>("", "accepted_scopes")
                .map_err(storage)?,
        )?,
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

async fn load_resource_unlocked(
    txn: &DatabaseTransaction,
    oid: ResourceOid,
) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{RESOURCE_SELECT} WHERE r.oid = $1"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
    resource_from_row(&row)
}

async fn load_resource_locked(
    txn: &DatabaseTransaction,
    oid: ResourceOid,
) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{RESOURCE_SELECT} WHERE r.oid = $1 FOR UPDATE OF r"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
    resource_from_row(&row)
}

fn ensure_not_reserved(record: &ApiResourceRecord) -> Result<(), RbacManagementRepositoryError> {
    if record.uri == API_RESOURCE {
        return Err(RbacManagementRepositoryError::Protected(
            identity_application::rbac::RbacProtectedKind::ReservedResource,
        ));
    }
    Ok(())
}

impl RbacManagementRepositoryImpl {
    pub(crate) async fn resource_find(
        &self,
        oid: ResourceOid,
    ) -> Result<Option<ApiResourceRecord>, RbacManagementRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                format!("{RESOURCE_SELECT} WHERE r.oid = $1"),
                [Uuid::from(oid).into()],
            ))
            .await
            .map_err(storage)?;
        row.as_ref().map(resource_from_row).transpose()
    }

    pub(crate) async fn resource_list(
        &self,
        query: ResourceQuery,
    ) -> Result<RbacPageData<ResourcePageEntry>, RbacManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let column = match query.order {
            identity_application::rbac::ResourceOrder::CreatedAtAsc
            | identity_application::rbac::ResourceOrder::CreatedAtDesc => "r.created_at",
            identity_application::rbac::ResourceOrder::NameAsc
            | identity_application::rbac::ResourceOrder::NameDesc => "r.name",
            identity_application::rbac::ResourceOrder::UriAsc
            | identity_application::rbac::ResourceOrder::UriDesc => "r.uri",
        };
        let mut binds = Binds::new();
        let mut conditions = vec!["1=1".to_owned()];
        if let Some(term) = &query.filter.query {
            let pattern = format!("%{}%", escape_like(term));
            let first = binds.push(pattern.clone());
            let second = binds.push(pattern);
            conditions.push(format!("(r.name ILIKE {first} OR r.uri ILIKE {second})"));
        }
        if let Some(enabled) = query.filter.enabled {
            conditions.push(format!("r.enabled = {}", binds.push(enabled)));
        }
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                column,
                "r.oid",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                column,
                "r.oid",
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
            "{RESOURCE_SELECT} WHERE {where_sql} \
             ORDER BY {column} {direction_sql}, r.oid {direction_sql} LIMIT {limit_placeholder}"
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
            let record = resource_from_row(&row)?;
            let tie = RbacTie::Oid(Uuid::from(record.oid));
            let sort_key = match query.order {
                identity_application::rbac::ResourceOrder::CreatedAtAsc
                | identity_application::rbac::ResourceOrder::CreatedAtDesc => {
                    RbacSortKey::CreatedAt {
                        created_at: record.created_at,
                        tie,
                    }
                }
                identity_application::rbac::ResourceOrder::NameAsc
                | identity_application::rbac::ResourceOrder::NameDesc => RbacSortKey::Text {
                    value: record.name.clone(),
                    tie,
                },
                identity_application::rbac::ResourceOrder::UriAsc
                | identity_application::rbac::ResourceOrder::UriDesc => RbacSortKey::Text {
                    value: record.uri.clone(),
                    tie,
                },
            };
            items.push(ResourcePageEntry { sort_key, record });
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

    pub(crate) async fn resource_create(
        &self,
        command: CreateResourceTransaction,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::ResourcesWrite,
            None,
        )
        .await?;
        if command.uri == API_RESOURCE {
            return Err(RbacManagementRepositoryError::Protected(
                identity_application::rbac::RbacProtectedKind::ReservedResource,
            ));
        }
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO resource(oid, uri, name, enabled, version, created_at) \
                 VALUES($1, $2, $3, true, gen_random_uuid(), now()) \
                 ON CONFLICT (uri) DO NOTHING RETURNING oid",
                [
                    Uuid::from(command.resource_oid).into(),
                    command.uri.into(),
                    command.name.into(),
                ],
            ))
            .await
            .map_err(storage)?;
        if row.is_none() {
            return Err(RbacManagementRepositoryError::Duplicate(
                identity_application::rbac::RbacDuplicateKind::ResourceUri,
            ));
        }
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.resource.create",
            "resource",
            Uuid::from(command.resource_oid),
            &command.reason,
        )
        .await?;
        let record = load_resource_unlocked(&txn, command.resource_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn resource_update(
        &self,
        command: UpdateResourceTransaction,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::ResourcesWrite,
            None,
        )
        .await?;
        let current = load_resource_locked(&txn, command.resource_oid).await?;
        ensure_not_reserved(&current)?;
        if current.version != command.expected_version {
            return Err(RbacManagementRepositoryError::VersionConflict {
                current_version: current.version,
            });
        }
        let Some(name) = command.name else {
            return Err(RbacManagementRepositoryError::EmptyUpdate);
        };
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE resource SET name = $2, version = gen_random_uuid(), \
              updated_at = now() WHERE oid = $1",
            [Uuid::from(command.resource_oid).into(), name.into()],
        ))
        .await
        .map_err(storage)?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.resource.update",
            "resource",
            Uuid::from(command.resource_oid),
            &command.reason,
        )
        .await?;
        let record = load_resource_unlocked(&txn, command.resource_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }

    pub(crate) async fn resource_set_enabled(
        &self,
        command: ResourceStateTransaction,
        enabled: bool,
    ) -> Result<ApiResourceRecord, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::ResourcesWrite,
            None,
        )
        .await?;
        let current = load_resource_locked(&txn, command.resource_oid).await?;
        ensure_not_reserved(&current)?;
        if current.version != command.expected_version {
            return Err(RbacManagementRepositoryError::VersionConflict {
                current_version: current.version,
            });
        }
        if current.enabled == enabled {
            txn.commit().await.map_err(storage)?;
            return Ok(current);
        }
        if enabled {
            let rows = txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT id FROM \"scope\" WHERE resource_id = $1 AND enabled = true ORDER BY id",
                    [Uuid::from(command.resource_oid).into()],
                ))
                .await
                .map_err(storage)?;
            let scope_ids = rows
                .into_iter()
                .map(|row| row.try_get::<i64>("", "id").map_err(storage))
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
            super::delegation::ensure_delegable_permissions(&txn, &command.authority, &scope_ids)
                .await?;
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE resource SET enabled = $2, version = gen_random_uuid(), \
              updated_at = now() WHERE oid = $1",
            [Uuid::from(command.resource_oid).into(), enabled.into()],
        ))
        .await
        .map_err(storage)?;
        withdraw_resource_authorization_artifacts(&txn, Uuid::from(command.resource_oid))
            .await
            .map_err(storage)?;
        withdraw_users_affected_by_resource(&txn, Uuid::from(command.resource_oid)).await?;
        append_semantic_audit(
            &txn,
            &command.authority,
            if enabled {
                "rbac.resource.enable"
            } else {
                "rbac.resource.disable"
            },
            "resource",
            Uuid::from(command.resource_oid),
            &command.reason,
        )
        .await?;
        let record = load_resource_unlocked(&txn, command.resource_oid).await?;
        txn.commit().await.map_err(storage)?;
        Ok(record)
    }
}
