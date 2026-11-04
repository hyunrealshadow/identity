//! Client API-scope delegation over the canonical `client_scope` relation.
//!
//! API-scope replacement is exact and only touches resource-owned scope rows;
//! protocol/identity assignments (`resource_id IS NULL`) are preserved. Built-in
//! definitions may be referenced but never edited here.

use std::collections::{BTreeMap, BTreeSet};

use identity_application::rbac::{
    ClientScopeAssignment, ClientScopePageEntry, ClientScopeQuery, ClientScopeSetResult,
    ClientScopeTargetPageEntry, ClientScopeTargetQuery, ClientScopeTargetRecord, RbacEntityKind,
    RbacManagementRepositoryError, RbacPageData, RbacProtectedKind, ScopeOrder,
    SetClientScopesTransaction,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{authorization::ManagementScope, client::model::ClientOid};
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
use uuid::Uuid;

use super::{
    RbacManagementRepositoryImpl,
    audit::append_semantic_audit,
    authority::recheck_authority,
    catalog::{ensure_assignable_api_scope, resolve_scopes},
    delegation,
    scope::scope_from_row,
    support::{
        Binds, CursorComparison, corrupt, escape_like, keyset_condition, not_found,
        order_is_descending, page_flags, storage,
    },
};
use crate::database::client_authorization_boundary;

const CLIENT_TARGET_SELECT: &str = "SELECT c.id, c.oid, c.name, c.built_in, \
            count(cs.id)::bigint AS allowed_scope_count, \
            c.version AS version \
     FROM client c \
     LEFT JOIN client_scope cs ON cs.client_id = c.id";

const CLIENT_SCOPE_SELECT: &str = "SELECT s.id, s.oid, s.resource_id, s.code, s.name, s.names, \
            s.description, s.descriptions, s.built_in, s.enabled, s.version, s.created_at, s.updated_at, \
            cs.client_granted \
     FROM \"scope\" s JOIN client_scope cs ON cs.scope_id = s.id \
     JOIN client c ON c.id = cs.client_id";

impl RbacManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "client_scope.count"))]
    pub(crate) async fn client_scope_count(
        &self,
        client_oid: ClientOid,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let row = self.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            format!("SELECT count(*)::bigint AS total_count FROM ({CLIENT_SCOPE_SELECT} WHERE c.oid = $1) counted"),
            [client_oid.into()])).await.map_err(storage)?.ok_or_else(corrupt)?;
        let value = row.try_get::<i64>("", "total_count").map_err(storage)?;
        u64::try_from(value).map_err(|_| corrupt())
    }

    pub(crate) async fn client_target_list(
        &self,
        query: ClientScopeTargetQuery,
    ) -> Result<RbacPageData<ClientScopeTargetPageEntry>, RbacManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let mut conditions = vec!["c.built_in = false".to_owned()];
        if let Some(term) = &query.filter.query {
            let pattern = format!("%{}%", escape_like(term));
            conditions.push(format!("c.name ILIKE {}", binds.push(pattern)));
        }
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "c.name",
                "c.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "c.name",
                "c.id",
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
            "{CLIENT_TARGET_SELECT} WHERE {where_sql} \
             GROUP BY c.id, c.oid, c.name, c.built_in, c.version \
             ORDER BY c.name {direction_sql}, c.id {direction_sql} LIMIT {limit_placeholder}"
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
            let version = row
                .try_get::<Option<Uuid>>("", "version")
                .map_err(storage)?
                .ok_or_else(corrupt)?;
            let record = ClientScopeTargetRecord {
                client_oid: row.try_get::<Uuid>("", "oid").map_err(storage)?,
                name: row.try_get::<String>("", "name").map_err(storage)?,
                built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
                allowed_scope_count: row
                    .try_get::<i64>("", "allowed_scope_count")
                    .map_err(storage)?,
                version,
            };
            let sort_key = RbacSortKey::Text {
                value: record.name.clone(),
                tie: RbacTie::Id(id),
            };
            items.push(ClientScopeTargetPageEntry { sort_key, record });
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

    pub(crate) async fn client_scope_list(
        &self,
        query: ClientScopeQuery,
    ) -> Result<RbacPageData<ClientScopePageEntry>, RbacManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let column = match query.order {
            ScopeOrder::CreatedAtAsc | ScopeOrder::CreatedAtDesc => "s.created_at",
            ScopeOrder::CodeAsc | ScopeOrder::CodeDesc => "s.code",
        };
        let mut binds = Binds::new();
        let client_placeholder = binds.push(query.client_oid);
        let mut conditions = vec![format!("c.oid = {client_placeholder}")];
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
            "{CLIENT_SCOPE_SELECT} WHERE {where_sql} \
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
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let record = scope_from_row(&row)?;
            let client_granted = row.try_get::<bool>("", "client_granted").map_err(storage)?;
            let tie = RbacTie::Id(id);
            let sort_key = match query.order {
                ScopeOrder::CreatedAtAsc | ScopeOrder::CreatedAtDesc => RbacSortKey::CreatedAt {
                    created_at: record.created_at,
                    tie,
                },
                ScopeOrder::CodeAsc | ScopeOrder::CodeDesc => RbacSortKey::Text {
                    value: record.code.clone(),
                    tie,
                },
            };
            items.push(ClientScopePageEntry {
                sort_key,
                record,
                client_granted,
            });
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

    pub(crate) async fn client_scope_set(
        &self,
        command: SetClientScopesTransaction,
    ) -> Result<ClientScopeSetResult, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(
            &txn,
            &command.authority,
            ManagementScope::ClientsScopes,
            None,
        )
        .await?;
        let client_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id, built_in, version FROM client WHERE oid = $1 FOR UPDATE",
                [command.client_oid.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Client))?;
        let client_id = client_row.try_get::<i64>("", "id").map_err(storage)?;
        if client_row
            .try_get::<bool>("", "built_in")
            .map_err(storage)?
        {
            return Err(RbacManagementRepositoryError::Protected(
                RbacProtectedKind::BuiltInClient,
            ));
        }
        let current_version = client_row.try_get::<Uuid>("", "version").map_err(storage)?;
        if current_version != command.expected_version {
            return Err(RbacManagementRepositoryError::PolicyVersionStale { current_version });
        }
        let requested_oids = command
            .scopes
            .iter()
            .map(|assignment| assignment.scope_oid)
            .collect::<Vec<_>>();
        let scopes = resolve_scopes(&txn, &requested_oids).await?;
        let mut requested = BTreeMap::new();
        for (scope, assignment) in scopes.iter().zip(&command.scopes) {
            ensure_assignable_api_scope(scope)?;
            if assignment.client_granted && is_human_only_scope(&scope.code) {
                return Err(RbacManagementRepositoryError::ClientGrantNotAllowed {
                    scope: scope.code.clone(),
                });
            }
            requested.insert(scope.id, assignment.client_granted);
        }
        let current_rows = txn
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT s.id, cs.client_granted FROM client_scope cs \
                 JOIN \"scope\" s ON s.id = cs.scope_id \
                 WHERE cs.client_id = $1 AND s.resource_id IS NOT NULL",
                [client_id.into()],
            ))
            .await
            .map_err(storage)?;
        // Only API-scope assignments are replaced. Protocol/identity rows
        // (`resource_id IS NULL`) are a separate assignment class and survive
        // both non-empty and empty API replacements.
        let mut current = BTreeMap::new();
        for row in current_rows {
            current.insert(
                row.try_get::<i64>("", "id").map_err(storage)?,
                row.try_get::<bool>("", "client_granted").map_err(storage)?,
            );
        }
        let result_scopes = scopes
            .iter()
            .zip(&command.scopes)
            .map(|(scope, assignment)| ClientScopeAssignment {
                scope_oid: scope.oid,
                client_granted: assignment.client_granted,
            })
            .collect::<Vec<_>>();
        if current == requested {
            txn.commit().await.map_err(storage)?;
            return Ok(ClientScopeSetResult {
                client_oid: command.client_oid,
                version: current_version,
                scopes: result_scopes,
            });
        }
        // A new assignment, or a user-only assignment newly granted to the
        // client itself, extends authority and must stay within the actor's
        // own delegation ceiling.
        let extended = requested
            .iter()
            .filter(|(id, granted)| match current.get(*id) {
                None => true,
                Some(current_granted) => **granted && !*current_granted,
            })
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        delegation::ensure_delegable_permissions(&txn, &command.authority, &extended).await?;
        if !current.is_empty() {
            let mut binds = Binds::new();
            let client = binds.push(client_id);
            let ids = current
                .keys()
                .map(|id| binds.push(*id))
                .collect::<Vec<_>>()
                .join(", ");
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "DELETE FROM client_scope WHERE client_id = {client} AND scope_id IN ({ids})"
                ),
                binds.into_values(),
            ))
            .await
            .map_err(storage)?;
        }
        for (scope_id, client_granted) in &requested {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO client_scope(client_id, scope_id, client_granted, created_at) \
                 VALUES($1, $2, $3, now())",
                [
                    client_id.into(),
                    (*scope_id).into(),
                    (*client_granted).into(),
                ],
            ))
            .await
            .map_err(storage)?;
        }
        let updated = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE client SET version = gen_random_uuid(), updated_at = now() \
                 WHERE id = $1 RETURNING version",
                [client_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let version = updated.try_get::<Uuid>("", "version").map_err(storage)?;
        // Scope replacement is a real client boundary change. Withdraw every
        // prior artifact, including consumed code/RT parents, permanently.
        client_authorization_boundary::withdraw_client_authorizations(&txn, client_id)
            .await
            .map_err(storage)?;
        append_semantic_audit(
            &txn,
            &command.authority,
            "rbac.client_scopes.set",
            "client",
            command.client_oid,
            &command.reason,
        )
        .await?;
        txn.commit().await.map_err(storage)?;
        Ok(ClientScopeSetResult {
            client_oid: command.client_oid,
            version,
            scopes: result_scopes,
        })
    }
}

/// Human-only management scopes are never held by a client itself.
fn is_human_only_scope(code: &str) -> bool {
    ManagementScope::from_name(code).is_some_and(|scope| !scope.m2m_allowed())
}
