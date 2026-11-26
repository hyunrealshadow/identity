//! User-role binding persistence and effective-permission projection.

use identity_domain::audit::{AuditAction, AuditRecord};
use identity_domain::audit::{AuditField, AuditRef, AuditTargetKind};
use std::collections::{BTreeMap, BTreeSet};

use identity_application::rbac::{
    AccountPermissionPageEntry, AccountPermissionQuery, AccountPermissionRecord, AccountRoleGrant,
    AccountRolePageEntry, AccountRoleQuery, AssignUserRolesTransaction, AuthorizationSource,
    EffectiveGroupPermissionSourceRecord, EffectivePermissionPageData,
    EffectivePermissionPageEntry, EffectivePermissionQuery, EffectivePermissionRecord,
    EffectivePermissionSourceRecord, InheritedUserRoleRecord, RbacEntityKind,
    RbacManagementRepositoryError, RbacPageData, RevokeUserRolesTransaction, UserRoleGrant,
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
        page_flags, parse_localized_metadata, storage, utc,
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
    name: String,
    enabled: bool,
}

impl LockedRole {
    fn audit_ref(&self) -> AuditRef {
        AuditRef::new(
            AuditTargetKind::Role,
            Uuid::from(self.oid),
            self.name.clone(),
        )
    }
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
                "SELECT id, oid, name, enabled FROM \"role\" WHERE oid IN ({placeholders}) \
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
            name: row.try_get::<String>("", "name").map_err(storage)?,
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

async fn active_user_id_by_oid<C: ConnectionTrait>(
    db: &C,
    user_oid: UserOid,
) -> Result<Option<i64>, RbacManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM \"user\" WHERE oid = $1 AND enabled = true",
            [Uuid::from(user_oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.map(|row| row.try_get::<i64>("", "id").map_err(storage))
        .transpose()
}

fn account_role_union(user_placeholder: &str, source: Option<AuthorizationSource>) -> String {
    let direct = format!(
        "SELECT 'direct' AS kind, urb.oid AS tie_oid, urb.created_at AS granted_at, \
                r.oid AS role_oid, NULL::uuid AS group_oid \
         FROM user_role urb \
         JOIN \"role\" r ON r.id = urb.role_id AND r.enabled = true \
         WHERE urb.user_id = {user_placeholder} \
           AND urb.enabled = true AND urb.revoked_at IS NULL"
    );
    let group = format!(
        "SELECT 'group' AS kind, grb.oid AS tie_oid, \
                GREATEST(gm.created_at, grb.created_at) AS granted_at, \
                r.oid AS role_oid, ug.oid AS group_oid \
         FROM group_membership gm \
         JOIN user_group ug ON ug.id = gm.group_id AND ug.enabled = true AND ug.deleted_at IS NULL \
         JOIN group_role grb ON grb.group_id = ug.id AND grb.enabled = true AND grb.revoked_at IS NULL \
         JOIN \"role\" r ON r.id = grb.role_id AND r.enabled = true \
         WHERE gm.user_id = {user_placeholder} \
           AND gm.enabled = true AND gm.revoked_at IS NULL"
    );
    match source {
        None => format!("{direct} UNION ALL {group}"),
        Some(AuthorizationSource::Direct) => direct,
        Some(AuthorizationSource::Group) => group,
    }
}

fn account_permission_conditions(
    user_id: i64,
    resource_oid: Option<ResourceOid>,
    source: Option<AuthorizationSource>,
    binds: &mut Binds,
) -> Vec<String> {
    let user_placeholder = binds.push(user_id);
    let api_resource_placeholder = binds.push(API_RESOURCE);
    let trusted = ManagementScope::ALL
        .into_iter()
        .map(|scope| {
            let oid = binds.push(rbac::built_in_permission_oid(scope).0);
            let name = binds.push(scope.name().to_owned());
            format!("(s.oid = {oid} AND s.code = {name})")
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let mut conditions = vec![
        "res.enabled = true".to_owned(),
        "s.enabled = true".to_owned(),
        format!("(res.uri <> {api_resource_placeholder} OR (s.built_in = true AND ({trusted})))"),
        effective_source_condition(&user_placeholder, source),
    ];
    if let Some(resource_oid) = resource_oid {
        conditions.push(format!(
            "s.resource_id = {}",
            binds.push(Uuid::from(resource_oid))
        ));
    }
    conditions
}

async fn load_direct_permission_sources(
    txn: &DatabaseTransaction,
    user_id: i64,
    permission_ids: &[i64],
) -> Result<BTreeMap<i64, Vec<EffectivePermissionSourceRecord>>, RbacManagementRepositoryError> {
    if permission_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
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
            user_role_oid: UserRoleOid(row.try_get::<Uuid>("", "user_role_oid").map_err(storage)?),
            role_oid: RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?),
        };
        map.entry(permission_id).or_default().push(source);
    }
    for sources in map.values_mut() {
        sources.sort_by_key(|source| (source.role_oid.0, source.user_role_oid.0));
    }
    Ok(map)
}

async fn load_group_permission_sources(
    txn: &DatabaseTransaction,
    user_id: i64,
    permission_ids: &[i64],
) -> Result<BTreeMap<i64, Vec<EffectiveGroupPermissionSourceRecord>>, RbacManagementRepositoryError>
{
    let mut group_sources: BTreeMap<i64, Vec<EffectiveGroupPermissionSourceRecord>> =
        BTreeMap::new();
    if permission_ids.is_empty() {
        return Ok(group_sources);
    }
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
                "SELECT rp.scope_id, ug.oid AS group_oid, gm.oid AS membership_oid, \
                        grb.oid AS group_role_oid, r.oid AS role_oid \
                 FROM group_membership gm \
                 JOIN user_group ug ON ug.id = gm.group_id AND ug.enabled = true AND ug.deleted_at IS NULL \
                 JOIN group_role grb ON grb.group_id = ug.id AND grb.enabled = true AND grb.revoked_at IS NULL \
                 JOIN \"role\" r ON r.id = grb.role_id AND r.enabled = true \
                 JOIN role_permission rp ON rp.role_id = r.id \
                 WHERE gm.user_id = {user_placeholder} AND gm.enabled = true AND gm.revoked_at IS NULL \
                   AND rp.scope_id IN ({placeholders})"
            ),
            source_binds.into_values(),
        ))
        .await
        .map_err(storage)?;
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
    Ok(group_sources)
}

mod reads;
mod writes;
