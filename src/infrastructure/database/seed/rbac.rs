//! Trusted built-in RBAC definitions.
//!
//! This seed is the version-controlled source for the built-in management
//! scope associations, the owner/admin/viewer role presets and their matching
//! groups. Runtime CRUD never edits these definitions. The seed:
//!
//! - derives identities only from the compiled management catalog;
//! - resolves a preset by its internal OID and refuses to adopt a non-built-in
//!   row that already occupies that identity;
//! - keeps fixed role-scope and group-role relations exact;
//! - never touches user group memberships or historical revoked relations;
//! - preserves identities while refreshing display text and fixed definitions.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use identity_domain::{
    authorization::catalog::{AdministratorRole, ManagementScope, validate_catalog},
    rbac::{
        LocalizedMetadata, LocalizedText, RolePermissionOid, built_in_group_oid,
        built_in_permission_oid, built_in_role_oid,
    },
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, Statement,
    TransactionTrait,
};
use uuid::Uuid;

use super::{Seed, oauth_resource};
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

    let mut role_ids: BTreeMap<AdministratorRole, i64> = BTreeMap::new();
    for role in AdministratorRole::ALL {
        let role_id = ensure_role(transaction, role).await?;
        ensure_role_permissions(transaction, role_id, role, &scope_ids).await?;
        role_ids.insert(role, role_id);
    }

    for role in AdministratorRole::ALL {
        let role_id = *role_ids
            .get(&role)
            .ok_or_else(|| internal("built-in role id is missing"))?;
        let group_id = ensure_group(transaction, role).await?;
        ensure_group_role_binding(transaction, group_id, role_id, built_in_group_oid(role).0)
            .await?;
    }

    Ok(())
}

fn internal(message: &'static str) -> AppError {
    AppError::internal(DbErr::Custom(message.to_owned()))
}

fn identity_conflict() -> AppError {
    AppError::from_code(RbacErrorCode::BuiltInIdentityConflict)
}

fn role_metadata(role: AdministratorRole) -> Result<LocalizedMetadata, AppError> {
    let (name_en, name_zh, description_en, description_zh) = match role {
        AdministratorRole::Owner => (
            "Owner",
            "所有者",
            "Complete instance administration authority",
            "完整的实例管理权限",
        ),
        AdministratorRole::Admin => (
            "Administrator",
            "管理员",
            "Manages users, clients, resources and authorization within the instance",
            "管理实例中的用户、客户端、资源和授权",
        ),
        AdministratorRole::Viewer => (
            "Viewer",
            "查看者",
            "Read-only access to instance management views",
            "只读访问实例管理视图",
        ),
    };
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

fn group_metadata(role: AdministratorRole) -> Result<LocalizedMetadata, AppError> {
    let (name_en, name_zh, description_en, description_zh) = match role {
        AdministratorRole::Owner => (
            "Owners",
            "所有者",
            "Members receive the complete owner role preset",
            "成员取得完整的所有者角色预设",
        ),
        AdministratorRole::Admin => (
            "Administrators",
            "管理员",
            "Members receive the administrator role preset",
            "成员取得管理员角色预设",
        ),
        AdministratorRole::Viewer => (
            "Viewers",
            "查看者",
            "Members receive the read-only viewer role preset",
            "成员取得只读查看者角色预设",
        ),
    };
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
    role: AdministratorRole,
) -> Result<i64, AppError> {
    let oid = built_in_role_oid(role).0;
    let metadata = role_metadata(role)?;
    let (names, descriptions, name, description) = metadata_values(&metadata)?;
    let description = description.unwrap_or_default();
    let row = transaction.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id,oid,built_in,name,description,names,descriptions FROM role WHERE oid=$1 FOR UPDATE",
        [oid.into()])).await.map_err(AppError::internal)?;
    if let Some(row) = row {
        if row.try_get::<Uuid>("", "oid").map_err(AppError::internal)? != oid
            || !row
                .try_get::<bool>("", "built_in")
                .map_err(AppError::internal)?
        {
            return Err(identity_conflict());
        }
        let changed = row
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
                "UPDATE role SET name=$2,description=$3,names=$4::jsonb,descriptions=$5::jsonb,version=gen_random_uuid(),updated_at=now() WHERE oid=$1",
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
    role: AdministratorRole,
    scope_ids: &BTreeMap<ManagementScope, i64>,
) -> Result<(), AppError> {
    let desired: BTreeSet<i64> = ManagementScope::ALL
        .into_iter()
        .filter(|scope| scope.allows_role(role))
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
        built_in_role_oid(role).0,
    )
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn advance_users_affected_by_role(
    transaction: &DatabaseTransaction,
    role_id: i64,
) -> Result<(), AppError> {
    let rows = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT user_id FROM (
    SELECT binding.user_id
    FROM user_role binding
    WHERE binding.role_id = $1
      AND binding.enabled = true
      AND binding.revoked_at IS NULL
    UNION
    SELECT membership.user_id
    FROM group_role relation
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
        .map_err(AppError::internal)?;
    for row in rows {
        let user_id = row
            .try_get::<i64>("", "user_id")
            .map_err(AppError::internal)?;
        authorization_lifecycle::withdraw_user_authority_in_txn(transaction, user_id)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

async fn ensure_group(
    transaction: &DatabaseTransaction,
    role: AdministratorRole,
) -> Result<i64, AppError> {
    let oid = built_in_group_oid(role).0;
    let metadata = group_metadata(role)?;
    let (names, descriptions, name, description) = metadata_values(&metadata)?;
    let row = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id,oid,built_in,name,description,names,descriptions FROM user_group WHERE oid=$1 FOR UPDATE",
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
        if row
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
                "UPDATE user_group SET names=$2::jsonb,descriptions=$3::jsonb,name=$4,description=$5,version=gen_random_uuid(),updated_at=now() WHERE oid=$1",
                [oid.into(),names.into(),descriptions.into(),name.into(),description.unwrap_or_default().into()])).await.map_err(AppError::internal)?;
        }
        return row.try_get::<i64>("", "id").map_err(AppError::internal);
    }
    let row = transaction.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO user_group(oid,names,descriptions,name,description,built_in) VALUES($1,$2::jsonb,$3::jsonb,$4,$5,true) RETURNING id",
        [oid.into(),names.into(),descriptions.into(),name.into(),description.unwrap_or_default().into()])).await.map_err(AppError::internal)?.ok_or_else(||internal("built-in group insert returned no row"))?;
    row.try_get::<i64>("", "id").map_err(AppError::internal)
}

async fn ensure_group_role_binding(
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
