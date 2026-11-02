//! Scope-catalog resolution helpers shared by RBAC write paths.

use identity_application::rbac::{RbacManagementRepositoryError, ScopeOid};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use uuid::Uuid;

use super::support::{Binds, corrupt, storage};

#[derive(Debug, Clone)]
pub(crate) struct ResolvedScope {
    pub id: i64,
    pub oid: ScopeOid,
    /// Stable machine token persisted in `scope.code`.
    pub code: String,
    pub enabled: bool,
    /// `None` marks a protocol/identity scope.
    pub resource_id: Option<Uuid>,
}

pub(crate) async fn resolve_scopes<C: ConnectionTrait>(
    db: &C,
    scope_oids: &[ScopeOid],
) -> Result<Vec<ResolvedScope>, RbacManagementRepositoryError> {
    if scope_oids.is_empty() {
        return Ok(Vec::new());
    }
    let mut binds = Binds::new();
    let placeholders = scope_oids
        .iter()
        .map(|oid| binds.push(oid.0))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT id, oid, code, enabled, resource_id \
                 FROM \"scope\" WHERE oid IN ({placeholders})"
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?;
    let mut resolved = Vec::with_capacity(rows.len());
    for row in rows {
        resolved.push(ResolvedScope {
            id: row.try_get::<i64>("", "id").map_err(storage)?,
            oid: ScopeOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
            code: row.try_get::<String>("", "code").map_err(storage)?,
            enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
            resource_id: row
                .try_get::<Option<Uuid>>("", "resource_id")
                .map_err(storage)?,
        });
    }
    if resolved.len() != scope_oids.len() {
        return Err(RbacManagementRepositoryError::NotFound(
            identity_application::rbac::RbacEntityKind::Scope,
        ));
    }
    // Preserve caller order and reject duplicate OIDs.
    let mut ordered = Vec::with_capacity(scope_oids.len());
    for requested in scope_oids {
        let scope = resolved
            .iter()
            .find(|scope| scope.oid == *requested)
            .cloned()
            .ok_or_else(corrupt)?;
        if ordered
            .iter()
            .any(|existing: &ResolvedScope| existing.oid == scope.oid)
        {
            return Err(RbacManagementRepositoryError::EmptyUpdate);
        }
        ordered.push(scope);
    }
    Ok(ordered)
}

/// A client API-scope assignment is an exact, live, resource-owned concrete
/// definition. Built-in definitions are assignable but remain immutable.
pub(crate) fn ensure_assignable_api_scope(
    scope: &ResolvedScope,
) -> Result<(), RbacManagementRepositoryError> {
    if scope.resource_id.is_none() || !scope.enabled || scope.code.contains('*') {
        return Err(RbacManagementRepositoryError::ScopeNotBusiness {
            scope: scope.code.clone(),
        });
    }
    Ok(())
}
