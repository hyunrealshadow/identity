//! User-role binding persistence and effective-permission projection.

use std::collections::{BTreeMap, BTreeSet};

use identity_application::rbac::{
    AssignUserRolesTransaction, AuthorizationSource, EffectiveGroupPermissionSourceRecord,
    EffectivePermissionPageData, EffectivePermissionPageEntry, EffectivePermissionQuery,
    EffectivePermissionRecord, EffectivePermissionSourceRecord, InheritedUserRoleRecord,
    RbacEntityKind, RbacManagementRepositoryError, RevokeUserRolesTransaction, UserRoleGrant,
    UserRoleGrantPageData, UserRoleGrantPageEntry, UserRoleGrantQuery, UserRoleMutationResult,
    UserRolePageData, UserRolePageEntry, UserRoleQuery, UserRoleRecord,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{
    authorization::{ActorPrincipal, ManagementScope},
    openid_connect::API_RESOURCE,
    rbac,
    rbac::{
        GroupMembershipOid, GroupOid, GroupRoleOid, ResourceOid, ResourcePermissionOid, RoleOid,
        UserRoleOid,
    },
    user::UserOid,
};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, Statement, TransactionTrait, Value,
};
use uuid::Uuid;

use super::{
    super::authorization_lifecycle,
    RbacManagementRepositoryImpl,
    audit::append_semantic_audit,
    authority::{recheck_authority, user_id_by_oid},
    delegation,
    support::{
        Binds, CursorComparison, corrupt, keyset_condition, not_found, order_is_descending,
        page_flags, storage, utc,
    },
};

const BINDING_SELECT: &str = "SELECT urb.id, urb.oid, urb.user_id, u.oid AS user_oid, urb.role_id, r.oid AS role_oid, \
            urb.granted_by_user_id, gbu.oid AS granted_by_user_oid, urb.reason, urb.enabled, \
            urb.revoked_at, urb.version, urb.created_at, urb.updated_at, \
            u.version AS user_version \
     FROM user_role urb \
     JOIN \"user\" u ON u.id = urb.user_id \
     JOIN \"role\" r ON r.id = urb.role_id \
     LEFT JOIN \"user\" gbu ON gbu.id = urb.granted_by_user_id";

fn binding_from_row(
    row: &sea_orm::QueryResult,
) -> Result<UserRoleRecord, RbacManagementRepositoryError> {
    Ok(UserRoleRecord {
        oid: UserRoleOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        user_oid: UserOid(row.try_get::<Uuid>("", "user_oid").map_err(storage)?),
        role_oid: RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?),
        granted_by_user_oid: row
            .try_get::<Option<Uuid>>("", "granted_by_user_oid")
            .map_err(storage)?
            .map(UserOid),
        reason: row.try_get::<String>("", "reason").map_err(storage)?,
        enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        revoked_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "revoked_at")
            .map_err(storage)?
            .map(utc),
        version: row.try_get::<Uuid>("", "version").map_err(storage)?,
        user_version: row.try_get::<Uuid>("", "user_version").map_err(storage)?,
        created_at: utc(row
            .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "created_at")
            .map_err(storage)?),
        updated_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
            .map_err(storage)?
            .map(utc),
    })
}

async fn current_user_version(
    txn: &DatabaseTransaction,
    user_id: i64,
) -> Result<Uuid, RbacManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT version FROM \"user\" WHERE id = $1",
            [user_id.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
    row.try_get::<Uuid>("", "version").map_err(storage)
}

struct LockedRole {
    id: i64,
    oid: RoleOid,
    enabled: bool,
}

async fn lock_roles(
    txn: &DatabaseTransaction,
    role_oids: &[RoleOid],
) -> Result<Vec<LockedRole>, RbacManagementRepositoryError> {
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
        return Err(not_found(RbacEntityKind::Role));
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

/// Live sources of one scope for one user. `None` keeps either source.
fn effective_source_condition(
    user_placeholder: &str,
    source: Option<AuthorizationSource>,
) -> String {
    let direct = format!(
        "EXISTS (SELECT 1 FROM user_role urb \
                 JOIN \"role\" r ON r.id = urb.role_id AND r.enabled = true \
          JOIN role_permission rp_membership \
            ON rp_membership.role_id = r.id AND rp_membership.scope_id = s.id \
          WHERE urb.user_id = {user_placeholder} AND urb.enabled = true \
            AND urb.revoked_at IS NULL)"
    );
    let group = format!(
        "EXISTS (SELECT 1 FROM group_membership gm \
            JOIN user_group ug ON ug.id = gm.group_id AND ug.enabled = true AND ug.deleted_at IS NULL \
            JOIN group_role grb ON grb.group_id = ug.id \
              AND grb.enabled = true AND grb.revoked_at IS NULL \
            JOIN \"role\" gr ON gr.id = grb.role_id AND gr.enabled = true \
            JOIN role_permission grp ON grp.role_id = gr.id AND grp.scope_id = s.id \
            WHERE gm.user_id = {user_placeholder} AND gm.enabled = true AND gm.revoked_at IS NULL)"
    );
    match source {
        None => format!("({direct} OR {group})"),
        Some(AuthorizationSource::Direct) => direct,
        Some(AuthorizationSource::Group) => group,
    }
}

fn effective_permission_conditions(
    user_id: i64,
    resource_oid: ResourceOid,
    management_resource: bool,
    source: Option<AuthorizationSource>,
    binds: &mut Binds,
) -> Vec<String> {
    let resource_placeholder = binds.push(Uuid::from(resource_oid));
    let user_placeholder = binds.push(user_id);
    let mut conditions = vec![
        format!("s.resource_id = {resource_placeholder}"),
        "s.enabled = true".to_owned(),
        effective_source_condition(&user_placeholder, source),
        format!(
            "EXISTS (SELECT 1 FROM \"user\" subject WHERE subject.id = {user_placeholder} AND subject.enabled = true)"
        ),
    ];
    if management_resource {
        let trusted = ManagementScope::ALL
            .into_iter()
            .map(|scope| {
                let oid = binds.push(rbac::built_in_permission_oid(scope).0);
                let name = binds.push(scope.name().to_owned());
                format!("(s.oid = {oid} AND s.code = {name})")
            })
            .collect::<Vec<_>>()
            .join(" OR ");
        conditions.push(format!("s.built_in = true AND ({trusted})"));
    }
    conditions
}

/// Direct assignment rows of one user, projected to the grant-list columns.
fn direct_grant_select(user_placeholder: &str, enabled: Option<&str>) -> String {
    let enabled = enabled
        .map(|placeholder| format!(" AND urb.enabled = {placeholder}"))
        .unwrap_or_default();
    format!(
        "SELECT 'direct' AS kind, urb.oid AS tie_oid, urb.created_at AS granted_at, \
                r.oid AS role_oid, gbu.oid AS granted_by_user_oid, urb.reason, urb.enabled, \
                urb.revoked_at, urb.version, urb.updated_at, \
                NULL::uuid AS group_oid, NULL::uuid AS membership_oid \
         FROM user_role urb \
         JOIN \"role\" r ON r.id = urb.role_id \
         LEFT JOIN \"user\" gbu ON gbu.id = urb.granted_by_user_id \
         WHERE urb.user_id = {user_placeholder}{enabled}"
    )
}

/// Roles one user currently holds through an active membership in an enabled
/// group with an active group-role binding.
fn group_grant_select(user_placeholder: &str) -> String {
    format!(
        "SELECT 'group' AS kind, grb.oid AS tie_oid, \
                GREATEST(gm.created_at, grb.created_at) AS granted_at, \
                r.oid AS role_oid, NULL::uuid AS granted_by_user_oid, ''::text AS reason, \
                true AS enabled, NULL::timestamptz AS revoked_at, NULL::uuid AS version, \
                NULL::timestamptz AS updated_at, ug.oid AS group_oid, gm.oid AS membership_oid \
         FROM group_membership gm \
         JOIN user_group ug ON ug.id = gm.group_id AND ug.enabled = true AND ug.deleted_at IS NULL \
         JOIN group_role grb ON grb.group_id = ug.id AND grb.enabled = true AND grb.revoked_at IS NULL \
         JOIN \"role\" r ON r.id = grb.role_id \
         WHERE gm.user_id = {user_placeholder} AND gm.enabled = true AND gm.revoked_at IS NULL"
    )
}

impl RbacManagementRepositoryImpl {
    pub(crate) async fn user_version(
        &self,
        user_oid: UserOid,
    ) -> Result<Uuid, RbacManagementRepositoryError> {
        let Some(user_id) = user_id_by_oid(&self.db, user_oid).await? else {
            return Err(not_found(RbacEntityKind::User));
        };
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT version FROM \"user\" WHERE id = $1",
                [user_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        row.try_get::<Uuid>("", "version").map_err(storage)
    }

    pub(crate) async fn user_role_list(
        &self,
        query: UserRoleQuery,
    ) -> Result<UserRolePageData, RbacManagementRepositoryError> {
        // Page rows and the single-user version are read from one
        // REPEATABLE READ snapshot. A separate version query after the page
        // would let a concurrent assignment revoke the cursor's CAS metadata.
        let txn = self.db.begin().await.map_err(storage)?;
        txn.execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
        ))
        .await
        .map_err(storage)?;
        let user_version = match query.user_oid {
            Some(user_oid) => {
                let Some(user_id) = user_id_by_oid(&txn, user_oid).await? else {
                    return Err(not_found(RbacEntityKind::User));
                };
                Some(current_user_version(&txn, user_id).await?)
            }
            None => None,
        };
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let mut conditions = vec!["1=1".to_owned()];
        if let Some(user_oid) = query.user_oid {
            conditions.push(format!("u.oid = {}", binds.push(Uuid::from(user_oid))));
        }
        if let Some(role_oid) = query.role_oid {
            conditions.push(format!("r.oid = {}", binds.push(Uuid::from(role_oid))));
        }
        if let Some(enabled) = query.enabled {
            conditions.push(format!("urb.enabled = {}", binds.push(enabled)));
        }
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "urb.created_at",
                "urb.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "urb.created_at",
                "urb.id",
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
            "{BINDING_SELECT} WHERE {where_sql} \
             ORDER BY urb.created_at {direction_sql}, urb.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = txn
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
            let record = binding_from_row(&row)?;
            let sort_key = RbacSortKey::CreatedAt {
                created_at: record.created_at,
                tie: RbacTie::Id(id),
            };
            items.push(UserRolePageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(UserRolePageData {
            items,
            has_previous_page,
            has_next_page,
            user_version,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "user_role_grant_list"))]
    pub(crate) async fn user_role_grant_list(
        &self,
        query: UserRoleGrantQuery,
    ) -> Result<UserRoleGrantPageData, RbacManagementRepositoryError> {
        // Rows and the user version come from one REPEATABLE READ snapshot so
        // the version stays valid as the CAS input for this page.
        let txn = self.db.begin().await.map_err(storage)?;
        txn.execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
        ))
        .await
        .map_err(storage)?;
        let Some(user_id) = user_id_by_oid(&txn, query.user_oid).await? else {
            return Err(not_found(RbacEntityKind::User));
        };
        let user_version = current_user_version(&txn, user_id).await?;
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let user_placeholder = binds.push(user_id);
        let include_direct = query.source != Some(AuthorizationSource::Group);
        // Inherited roles are live grants; they have no revoked history.
        let include_group =
            query.source != Some(AuthorizationSource::Direct) && query.enabled != Some(false);
        let mut parts = Vec::with_capacity(2);
        if include_direct {
            let enabled = query.enabled.map(|enabled| binds.push(enabled));
            parts.push(direct_grant_select(&user_placeholder, enabled.as_deref()));
        }
        if include_group {
            parts.push(group_grant_select(&user_placeholder));
        }
        if parts.is_empty() {
            txn.commit().await.map_err(storage)?;
            return Ok(UserRoleGrantPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
                user_version,
            });
        }
        let mut conditions = vec!["1=1".to_owned()];
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "g.granted_at",
                "g.tie_oid",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "g.granted_at",
                "g.tie_oid",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push((query.limit + 1) as i64);
        let sql = format!(
            "SELECT g.* FROM ({}) g WHERE {} \
             ORDER BY g.granted_at {direction_sql}, g.tie_oid {direction_sql} LIMIT {limit_placeholder}",
            parts.join(" UNION ALL "),
            conditions.join(" AND "),
        );
        let rows = txn
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
            let tie_oid = row.try_get::<Uuid>("", "tie_oid").map_err(storage)?;
            let created_at = utc(row
                .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "granted_at")
                .map_err(storage)?);
            let role_oid = RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?);
            let kind = row.try_get::<String>("", "kind").map_err(storage)?;
            let grant = match kind.as_str() {
                "direct" => UserRoleGrant::Direct(UserRoleRecord {
                    oid: UserRoleOid(tie_oid),
                    user_oid: query.user_oid,
                    role_oid,
                    granted_by_user_oid: row
                        .try_get::<Option<Uuid>>("", "granted_by_user_oid")
                        .map_err(storage)?
                        .map(UserOid),
                    reason: row.try_get::<String>("", "reason").map_err(storage)?,
                    enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
                    revoked_at: row
                        .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "revoked_at")
                        .map_err(storage)?
                        .map(utc),
                    version: row
                        .try_get::<Option<Uuid>>("", "version")
                        .map_err(storage)?
                        .ok_or_else(corrupt)?,
                    user_version,
                    created_at,
                    updated_at: row
                        .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
                        .map_err(storage)?
                        .map(utc),
                }),
                "group" => UserRoleGrant::Group(InheritedUserRoleRecord {
                    user_oid: query.user_oid,
                    role_oid,
                    group_oid: GroupOid(
                        row.try_get::<Option<Uuid>>("", "group_oid")
                            .map_err(storage)?
                            .ok_or_else(corrupt)?,
                    ),
                    membership_oid: GroupMembershipOid(
                        row.try_get::<Option<Uuid>>("", "membership_oid")
                            .map_err(storage)?
                            .ok_or_else(corrupt)?,
                    ),
                    group_role_oid: GroupRoleOid(tie_oid),
                    created_at,
                }),
                _ => return Err(corrupt()),
            };
            let sort_key = RbacSortKey::CreatedAt {
                created_at,
                tie: RbacTie::Oid(tie_oid),
            };
            items.push(UserRoleGrantPageEntry { sort_key, grant });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(UserRoleGrantPageData {
            items,
            has_previous_page,
            has_next_page,
            user_version,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "effective_permission_count"))]
    pub(crate) async fn effective_count(
        &self,
        user_oid: UserOid,
        resource_oid: ResourceOid,
        source: Option<AuthorizationSource>,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        let user_id = user_id_by_oid(&txn, user_oid)
            .await?
            .ok_or_else(|| not_found(RbacEntityKind::User))?;
        let resource = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT uri, enabled FROM resource WHERE oid = $1",
                [Uuid::from(resource_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
        if !resource.try_get::<bool>("", "enabled").map_err(storage)? {
            txn.commit().await.map_err(storage)?;
            return Ok(0);
        }
        let management_resource =
            resource.try_get::<String>("", "uri").map_err(storage)? == API_RESOURCE;
        let mut binds = Binds::new();
        let conditions = effective_permission_conditions(
            user_id,
            resource_oid,
            management_resource,
            source,
            &mut binds,
        );
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT count(*)::bigint AS total_count FROM scope s WHERE {}",
                    conditions.join(" AND ")
                ),
                binds.into_values(),
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let total = u64::try_from(row.try_get::<i64>("", "total_count").map_err(storage)?)
            .map_err(|_| corrupt())?;
        txn.commit().await.map_err(storage)?;
        Ok(total)
    }

    pub(crate) async fn effective_list(
        &self,
        query: EffectivePermissionQuery,
    ) -> Result<EffectivePermissionPageData, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        let Some(user_id) = user_id_by_oid(&txn, query.user_oid).await? else {
            return Err(not_found(RbacEntityKind::User));
        };
        let version = current_user_version(&txn, user_id).await?;
        let resource_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT uri, enabled FROM resource WHERE oid = $1",
                [Uuid::from(query.resource_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
        let management_resource =
            resource_row.try_get::<String>("", "uri").map_err(storage)? == API_RESOURCE;
        let enabled = resource_row
            .try_get::<bool>("", "enabled")
            .map_err(storage)?;
        if !enabled {
            txn.commit().await.map_err(storage)?;
            return Ok(EffectivePermissionPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
                user_version: version,
            });
        }
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let mut conditions = effective_permission_conditions(
            user_id,
            query.resource_oid,
            management_resource,
            query.source,
            &mut binds,
        );
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "s.code",
                "s.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "s.code",
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
            "SELECT s.id, s.oid AS permission_oid, s.resource_id, s.code, s.code AS scope \
             FROM \"scope\" s WHERE {where_sql} \
             ORDER BY s.code {direction_sql}, s.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = txn
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
        let permission_ids = rows
            .iter()
            .map(|row| row.try_get::<i64>("", "id"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        let sources = if permission_ids.is_empty() {
            BTreeMap::new()
        } else {
            let mut source_binds = Binds::new();
            let user_placeholder = source_binds.push(user_id);
            let placeholders = permission_ids
                .iter()
                .map(|id| source_binds.push(*id))
                .collect::<Vec<_>>()
                .join(", ");
            let source_rows = txn
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    format!(
                        "SELECT urb.oid AS user_role_oid, r.oid AS role_oid, \
                                rp_membership.scope_id \
                         FROM user_role urb \
                  JOIN \"role\" r ON r.id = urb.role_id AND r.enabled = true \
                         JOIN role_permission rp_membership ON rp_membership.role_id = r.id \
                         WHERE urb.user_id = {user_placeholder} AND urb.enabled = true \
                           AND urb.revoked_at IS NULL \
                           AND rp_membership.scope_id IN ({placeholders})"
                    ),
                    source_binds.into_values(),
                ))
                .await
                .map_err(storage)?;
            let mut map: BTreeMap<i64, Vec<EffectivePermissionSourceRecord>> = BTreeMap::new();
            for row in source_rows {
                let permission_id = row.try_get::<i64>("", "scope_id").map_err(storage)?;
                let source = EffectivePermissionSourceRecord {
                    user_role_oid: UserRoleOid(
                        row.try_get::<Uuid>("", "user_role_oid").map_err(storage)?,
                    ),
                    role_oid: RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?),
                };
                map.entry(permission_id).or_default().push(source);
            }
            for sources in map.values_mut() {
                sources.sort_by_key(|source| (source.role_oid.0, source.user_role_oid.0));
            }
            map
        };
        let mut group_sources: BTreeMap<i64, Vec<EffectiveGroupPermissionSourceRecord>> =
            BTreeMap::new();
        if !permission_ids.is_empty() {
            let mut source_binds = Binds::new();
            let user_placeholder = source_binds.push(user_id);
            let placeholders = permission_ids
                .iter()
                .map(|id| source_binds.push(*id))
                .collect::<Vec<_>>()
                .join(", ");
            let source_rows = txn.query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("SELECT rp.scope_id, ug.oid AS group_oid, gm.oid AS membership_oid, \
                    grb.oid AS group_role_oid, r.oid AS role_oid \
                    FROM group_membership gm \
                    JOIN user_group ug ON ug.id = gm.group_id AND ug.enabled = true AND ug.deleted_at IS NULL \
                    JOIN group_role grb ON grb.group_id = ug.id AND grb.enabled = true AND grb.revoked_at IS NULL \
                    JOIN \"role\" r ON r.id = grb.role_id AND r.enabled = true \
                    JOIN role_permission rp ON rp.role_id = r.id \
                    WHERE gm.user_id = {user_placeholder} AND gm.enabled = true AND gm.revoked_at IS NULL \
                    AND rp.scope_id IN ({placeholders})"),
                source_binds.into_values(),
            )).await.map_err(storage)?;
            for row in source_rows {
                let permission_id = row.try_get::<i64>("", "scope_id").map_err(storage)?;
                group_sources.entry(permission_id).or_default().push(
                    EffectiveGroupPermissionSourceRecord {
                        group_oid: GroupOid(row.try_get::<Uuid>("", "group_oid").map_err(storage)?),
                        membership_oid: GroupMembershipOid(
                            row.try_get::<Uuid>("", "membership_oid").map_err(storage)?,
                        ),
                        group_role_oid: GroupRoleOid(
                            row.try_get::<Uuid>("", "group_role_oid").map_err(storage)?,
                        ),
                        role_oid: RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?),
                    },
                );
            }
            for sources in group_sources.values_mut() {
                sources.sort_by_key(|source| {
                    (
                        source.group_oid.0,
                        source.membership_oid.0,
                        source.group_role_oid.0,
                    )
                });
            }
        }
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let record = EffectivePermissionRecord {
                permission_oid: ResourcePermissionOid(
                    row.try_get::<Uuid>("", "permission_oid").map_err(storage)?,
                ),
                resource_oid: ResourceOid(
                    row.try_get::<Option<Uuid>>("", "resource_id")
                        .map_err(storage)?
                        .ok_or_else(corrupt)?,
                ),
                code: row.try_get::<String>("", "code").map_err(storage)?,
                scope: row.try_get::<String>("", "scope").map_err(storage)?,
                sources: sources.get(&id).cloned().unwrap_or_default(),
                group_sources: group_sources.get(&id).cloned().unwrap_or_default(),
            };
            let sort_key = RbacSortKey::Text {
                value: record.code.clone(),
                tie: RbacTie::Id(id),
            };
            items.push(EffectivePermissionPageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(EffectivePermissionPageData {
            items,
            has_previous_page,
            has_next_page,
            user_version: version,
        })
    }

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
            created.push((user_role_oid, role.oid));
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
        if created.is_empty() {
            append_semantic_audit(
                &txn,
                &command.authority,
                "rbac.user.roles.assign",
                "user",
                Uuid::from(command.user_oid),
                &command.reason,
            )
            .await?;
        } else {
            for (user_role_oid, _role_oid) in &created {
                append_semantic_audit(
                    &txn,
                    &command.authority,
                    "rbac.user.roles.assign",
                    "user_role",
                    Uuid::from(*user_role_oid),
                    &command.reason,
                )
                .await?;
            }
        }
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
        for user_role_oid in &user_role_oids {
            append_semantic_audit(
                &txn,
                &command.authority,
                "rbac.user.roles.revoke",
                "user_role",
                Uuid::from(*user_role_oid),
                &command.reason,
            )
            .await?;
        }
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
