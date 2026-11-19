//! Trusted built-in RBAC definitions.
//!
//! This seed writes the built-in management scopes and the built-in RBAC
//! presets (`identity_domain::rbac::BUILT_IN_PRESETS`): ordinary roles with
//! explicit permission sets and the groups that grant them. Runtime CRUD never
//! edits these definitions. The seed:
//!
//! - derives scope identities only from the compiled management catalog;
//! - resolves a preset by its internal OID and refuses to adopt a non-built-in
//!   row that already occupies that identity;
//! - keeps fixed role-scope and group-role relations exact;
//! - never touches user group memberships or historical revoked relations;
//! - preserves identities while refreshing display text and fixed definitions.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use identity_domain::{
    authorization::catalog::{
        ManagementScope, RENAMED_MANAGEMENT_SCOPES, RETIRED_MANAGEMENT_SCOPE_NAMES,
        validate_catalog,
    },
    rbac::{
        ADMIN_PRESET, BUILT_IN_PRESETS, BuiltInPreset, LocalizedMetadata, LocalizedText,
        OWNER_PRESET, RolePermissionOid, VIEWER_PRESET, built_in_permission_oid,
    },
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, Statement,
    TransactionTrait, Value,
};
use uuid::Uuid;

use super::{
    Seed, oauth_resource,
    scope::{advance_users_affected_by_role, copy_scope_relations, retire_built_in_scopes},
};
use crate::{
    application::error::{AppError, codes::rbac::RbacErrorCode},
    database::{
        audit,
        repository::{authorization_lifecycle, localized},
    },
};

pub struct UnifiedRbacSeed;

impl UnifiedRbacSeed {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for UnifiedRbacSeed {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Seed for UnifiedRbacSeed {
    fn name(&self) -> &'static str {
        "unified_rbac"
    }

    #[tracing::instrument(
        skip_all,
        name = "db.seed",
        fields(db.system = "postgresql", seed = "unified_rbac")
    )]
    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        let transaction = db.begin().await.map_err(AppError::internal)?;
        ensure_built_in_rbac(&transaction).await?;
        transaction.commit().await.map_err(AppError::internal)?;
        Ok(())
    }
}

/// Ensure every trusted scope association, role and group definition and its
/// fixed relations. Safe to run repeatedly and after a catalog version upgrade.
#[tracing::instrument(
    skip_all,
    name = "db.query",
    fields(db.system = "postgresql", db.operation = "ensure_built_in_rbac")
)]
pub async fn ensure_built_in_rbac(transaction: &DatabaseTransaction) -> Result<(), AppError> {
    authorization_lifecycle::lock_owner_lifecycle(transaction)
        .await
        .map_err(AppError::internal)?;
    validate_catalog().map_err(AppError::internal)?;

    let resource_oid = oauth_resource::graphql_resource_oid(transaction).await?;

    let mut scope_ids: BTreeMap<ManagementScope, i64> = BTreeMap::new();
    for scope in ManagementScope::ALL {
        let id = ensure_scope_id(transaction, resource_oid, scope).await?;
        scope_ids.insert(scope, id);
    }

    migrate_renamed_management_scopes(transaction, resource_oid, &scope_ids).await?;
    retire_management_scopes(transaction, resource_oid).await?;

    for preset in &BUILT_IN_PRESETS {
        let text = preset_text(preset)?;
        let role_id = ensure_role(transaction, preset, &text).await?;
        ensure_role_permissions(transaction, role_id, preset, &scope_ids).await?;
        let group_id = ensure_group(transaction, preset, &text).await?;
        ensure_group_role(transaction, group_id, role_id, preset.group_oid.0).await?;
    }

    Ok(())
}

/// Migrate exact 1-to-1 built-in management renames onto the new scope rows
/// before [`retire_management_scopes`] deletes the old definitions.
async fn migrate_renamed_management_scopes(
    transaction: &DatabaseTransaction,
    resource_oid: Uuid,
    scope_ids: &BTreeMap<ManagementScope, i64>,
) -> Result<(), AppError> {
    for (old_code, new_scope) in RENAMED_MANAGEMENT_SCOPES {
        let old_row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM \"scope\" WHERE built_in = true AND resource_id = $1 AND code = $2",
                [resource_oid.into(), old_code.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        let Some(old_row) = old_row else {
            continue;
        };
        let old_id = old_row
            .try_get::<i64>("", "id")
            .map_err(AppError::internal)?;
        let new_id = *scope_ids
            .get(&new_scope)
            .ok_or_else(|| internal("a built-in scope id is missing"))?;
        copy_scope_relations(transaction, old_id, new_id, new_scope.m2m_allowed()).await?;
    }
    Ok(())
}

/// Remove retired and obsolete built-in management scope definitions from an
/// existing database. Every role that still references one loses that
/// permission with version rotation, authority withdrawal and audit; client
/// assignments and consents follow through their cascading foreign keys and
/// trigger client authorization withdrawal.
async fn retire_management_scopes(
    transaction: &DatabaseTransaction,
    resource_oid: Uuid,
) -> Result<(), AppError> {
    let mut binds: Vec<Value> = vec![resource_oid.into()];
    let retired_placeholders = (2..=RETIRED_MANAGEMENT_SCOPE_NAMES.len() + 1)
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(", ");
    binds.extend(
        RETIRED_MANAGEMENT_SCOPE_NAMES
            .iter()
            .map(|name| (*name).into()),
    );

    let active_start = binds.len() + 1;
    let active_placeholders = (active_start..active_start + ManagementScope::ALL.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(", ");
    binds.extend(
        ManagementScope::ALL
            .into_iter()
            .map(|scope| scope.name().into()),
    );

    let rows = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT id FROM \"scope\" \
                 WHERE built_in = true \
                   AND ( \
                     code IN ({retired_placeholders}) \
                     OR ( \
                       resource_id = $1 \
                       AND code LIKE 'management.%' \
                       AND code NOT IN ({active_placeholders}) \
                     ) \
                   ) \
                 ORDER BY id"
            ),
            binds,
        ))
        .await
        .map_err(AppError::internal)?;
    let obsolete_ids: Vec<i64> = rows
        .into_iter()
        .map(|row| row.try_get::<i64>("", "id"))
        .collect::<Result<_, _>>()
        .map_err(AppError::internal)?;
    retire_built_in_scopes(transaction, &obsolete_ids).await
}

fn internal(message: &'static str) -> AppError {
    AppError::internal(DbErr::Custom(message.to_owned()))
}

fn identity_conflict() -> AppError {
    AppError::from_code(RbacErrorCode::BuiltInIdentityConflict)
}

/// Display text of one built-in preset's role and group.
struct PresetText {
    role: [&'static str; 4],
    group: [&'static str; 4],
}

/// Default and Simplified Chinese name and description, in that order:
/// `[name_en, name_zh, description_en, description_zh]`.
fn preset_text(preset: &BuiltInPreset) -> Result<PresetText, AppError> {
    if *preset == OWNER_PRESET {
        Ok(PresetText {
            role: [
                "Owner",
                "所有者",
                "Complete instance administration authority",
                "完整的实例管理权限",
            ],
            group: [
                "Owners",
                "所有者",
                "Grants the Owner role",
                "授予所有者角色",
            ],
        })
    } else if *preset == ADMIN_PRESET {
        Ok(PresetText {
            role: [
                "Administrator",
                "管理员",
                "Manages users, clients, resources and authorization within the instance",
                "管理实例中的用户、客户端、资源和授权",
            ],
            group: [
                "Administrators",
                "管理员",
                "Grants the Administrator role",
                "授予管理员角色",
            ],
        })
    } else if *preset == VIEWER_PRESET {
        Ok(PresetText {
            role: [
                "Viewer",
                "查看者",
                "Read-only access to instance management views",
                "只读访问实例管理视图",
            ],
            group: [
                "Viewers",
                "查看者",
                "Grants the Viewer role",
                "授予查看者角色",
            ],
        })
    } else {
        Err(internal("built-in preset has no display text"))
    }
}

fn localized_metadata(text: [&'static str; 4]) -> Result<LocalizedMetadata, AppError> {
    let [name_en, name_zh, description_en, description_zh] = text;
    LocalizedMetadata::canonicalize(
        vec![
            LocalizedText::new("en-US", name_en),
            LocalizedText::new("zh-CN", name_zh),
        ],
        vec![
            LocalizedText::new("en-US", description_en),
            LocalizedText::new("zh-CN", description_zh),
        ],
    )
    .map_err(AppError::internal)
}

fn text_map(entries: &[LocalizedText]) -> serde_json::Value {
    localized::encode_text(entries)
}

fn metadata_values(
    metadata: &LocalizedMetadata,
) -> Result<(String, String, String, Option<String>), AppError> {
    Ok((
        text_map(&metadata.names).to_string(),
        text_map(&metadata.descriptions).to_string(),
        metadata
            .base_name()
            .ok_or_else(|| internal("built-in metadata has no name"))?
            .to_owned(),
        metadata.base_description().map(str::to_owned),
    ))
}

async fn ensure_scope_id(
    transaction: &DatabaseTransaction,
    resource_oid: Uuid,
    scope: ManagementScope,
) -> Result<i64, AppError> {
    let row = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id, oid, built_in FROM \"scope\" WHERE code = $1 AND resource_id = $2",
            [scope.name().into(), resource_oid.into()],
        ))
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| internal("a trusted management scope row is missing"))?;
    if !row
        .try_get::<bool>("", "built_in")
        .map_err(AppError::internal)?
        || row.try_get::<Uuid>("", "oid").map_err(AppError::internal)?
            != built_in_permission_oid(scope).0
    {
        return Err(identity_conflict());
    }
    row.try_get::<i64>("", "id").map_err(AppError::internal)
}

async fn ensure_role(
    transaction: &DatabaseTransaction,
    preset: &BuiltInPreset,
    text: &PresetText,
) -> Result<i64, AppError> {
    let oid = preset.role_oid.0;
    let metadata = localized_metadata(text.role)?;
    let (names, descriptions, name, description) = metadata_values(&metadata)?;
    let description = description.unwrap_or_default();
    let row = transaction.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id,oid,built_in,enabled,name,description,names,descriptions FROM role WHERE oid=$1 FOR UPDATE",
        [oid.into()])).await.map_err(AppError::internal)?;
    if let Some(row) = row {
        if row.try_get::<Uuid>("", "oid").map_err(AppError::internal)? != oid
            || !row
                .try_get::<bool>("", "built_in")
                .map_err(AppError::internal)?
        {
            return Err(identity_conflict());
        }
        let changed = !row
            .try_get::<bool>("", "enabled")
            .map_err(AppError::internal)?
            || row
                .try_get::<String>("", "name")
                .map_err(AppError::internal)?
                != name
            || row
                .try_get::<String>("", "description")
                .map_err(AppError::internal)?
                != description
            || row
                .try_get::<serde_json::Value>("", "names")
                .map_err(AppError::internal)?
                != text_map(&metadata.names)
            || row
                .try_get::<serde_json::Value>("", "descriptions")
                .map_err(AppError::internal)?
                != text_map(&metadata.descriptions);
        if changed {
            transaction.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE role SET enabled=true,name=$2,description=$3,names=$4::jsonb,descriptions=$5::jsonb,version=gen_random_uuid(),updated_at=now() WHERE oid=$1",
                [oid.into(),name.into(),description.into(),names.into(),descriptions.into()])).await.map_err(AppError::internal)?;
        }
        return row.try_get::<i64>("", "id").map_err(AppError::internal);
    }
    let row = transaction.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO role(oid,name,description,names,descriptions,built_in) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,true) RETURNING id",
        [oid.into(),name.into(),description.into(),names.into(),descriptions.into()])).await.map_err(AppError::internal)?.ok_or_else(||internal("built-in role insert returned no row"))?;
    row.try_get::<i64>("", "id").map_err(AppError::internal)
}

async fn ensure_role_permissions(
    transaction: &DatabaseTransaction,
    role_id: i64,
    preset: &BuiltInPreset,
    scope_ids: &BTreeMap<ManagementScope, i64>,
) -> Result<(), AppError> {
    let desired: BTreeSet<i64> = preset
        .permissions
        .iter()
        .copied()
        .map(|scope| {
            scope_ids
                .get(&scope)
                .copied()
                .ok_or_else(|| internal("a built-in scope id is missing"))
        })
        .collect::<Result<_, AppError>>()?;

    let rows = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id, scope_id FROM role_permission WHERE role_id = $1",
            [role_id.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    let mut current = BTreeSet::new();
    for row in &rows {
        current.insert(
            row.try_get::<i64>("", "scope_id")
                .map_err(AppError::internal)?,
        );
    }
    if current == desired {
        return Ok(());
    }

    for row in rows {
        let scope_id = row
            .try_get::<i64>("", "scope_id")
            .map_err(AppError::internal)?;
        if !desired.contains(&scope_id) {
            let id = row.try_get::<i64>("", "id").map_err(AppError::internal)?;
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "DELETE FROM role_permission WHERE id = $1",
                    [id.into()],
                ))
                .await
                .map_err(AppError::internal)?;
        }
    }
    for scope_id in desired.difference(&current) {
        transaction
            .execute_raw(Statement::from_sql_and_values(
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
            .map_err(AppError::internal)?;
    }

    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE \"role\" SET version = gen_random_uuid(), \
                updated_at = now() WHERE id = $1",
            [role_id.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    advance_users_affected_by_role(transaction, role_id).await?;
    audit::record(
        transaction,
        "rbac.role.permissions.reconcile",
        "role",
        preset.role_oid.0,
    )
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn ensure_group(
    transaction: &DatabaseTransaction,
    preset: &BuiltInPreset,
    text: &PresetText,
) -> Result<i64, AppError> {
    let oid = preset.group_oid.0;
    let metadata = localized_metadata(text.group)?;
    let (names, descriptions, name, description) = metadata_values(&metadata)?;
    let row = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id,oid,built_in,enabled,name,description,names,descriptions FROM user_group WHERE oid=$1 FOR UPDATE",
            [oid.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    if let Some(row) = row {
        if row.try_get::<Uuid>("", "oid").map_err(AppError::internal)? != oid
            || !row
                .try_get::<bool>("", "built_in")
                .map_err(AppError::internal)?
        {
            return Err(identity_conflict());
        }
        if !row
            .try_get::<bool>("", "enabled")
            .map_err(AppError::internal)?
            || row
                .try_get::<String>("", "name")
                .map_err(AppError::internal)?
                != name
            || row
                .try_get::<String>("", "description")
                .map_err(AppError::internal)?
                != description.clone().unwrap_or_default()
            || row
                .try_get::<serde_json::Value>("", "names")
                .map_err(AppError::internal)?
                != text_map(&metadata.names)
            || row
                .try_get::<serde_json::Value>("", "descriptions")
                .map_err(AppError::internal)?
                != text_map(&metadata.descriptions)
        {
            transaction.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE user_group SET enabled=true,names=$2::jsonb,descriptions=$3::jsonb,name=$4,description=$5,version=gen_random_uuid(),updated_at=now() WHERE oid=$1",
                [oid.into(),names.into(),descriptions.into(),name.into(),description.unwrap_or_default().into()])).await.map_err(AppError::internal)?;
        }
        return row.try_get::<i64>("", "id").map_err(AppError::internal);
    }
    let row = transaction.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO user_group(oid,names,descriptions,name,description,built_in) VALUES($1,$2::jsonb,$3::jsonb,$4,$5,true) RETURNING id",
        [oid.into(),names.into(),descriptions.into(),name.into(),description.unwrap_or_default().into()])).await.map_err(AppError::internal)?.ok_or_else(||internal("built-in group insert returned no row"))?;
    row.try_get::<i64>("", "id").map_err(AppError::internal)
}

async fn ensure_group_role(
    transaction: &DatabaseTransaction,
    group_id: i64,
    role_id: i64,
    group_oid: Uuid,
) -> Result<(), AppError> {
    let rows = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id, role_id FROM group_role \
             WHERE group_id = $1 AND enabled = true AND revoked_at IS NULL FOR UPDATE",
            [group_id.into()],
        ))
        .await
        .map_err(AppError::internal)?;

    let mut has_target = false;
    let mut changed = false;
    for row in rows {
        let current_role = row
            .try_get::<i64>("", "role_id")
            .map_err(AppError::internal)?;
        if current_role == role_id {
            has_target = true;
            continue;
        }
        let id = row.try_get::<i64>("", "id").map_err(AppError::internal)?;
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE group_role SET enabled = false, revoked_at = now(), \
                    version = gen_random_uuid(), updated_at = now() \
                 WHERE id = $1",
                [id.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        changed = true;
    }

    if !has_target {
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO group_role(oid, group_id, role_id, granted_by_user_id, reason, \
                    enabled, created_at) \
                 VALUES($1, $2, $3, NULL, 'built_in_definition', true, now())",
                [Uuid::new_v4().into(), group_id.into(), role_id.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        changed = true;
    }

    if changed {
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE user_group SET version = gen_random_uuid(), \
                    updated_at = now() WHERE id = $1",
                [group_id.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        let members = transaction
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                r#"
SELECT user_id FROM group_membership
WHERE group_id=$1 AND enabled=true AND revoked_at IS NULL
ORDER BY user_id
"#,
                [group_id.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        for row in members {
            let user_id = row
                .try_get::<i64>("", "user_id")
                .map_err(AppError::internal)?;
            authorization_lifecycle::withdraw_user_authority_in_txn(transaction, user_id)
                .await
                .map_err(AppError::internal)?;
        }
        audit::record(
            transaction,
            "rbac.group.roles.reconcile",
            "user_group",
            group_oid,
        )
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}
