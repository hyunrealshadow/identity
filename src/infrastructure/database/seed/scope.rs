use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::Utc;
use identity_domain::{
    authorization::catalog::{ManagementScope, RETIRED_MANAGEMENT_SCOPE_NAMES},
    rbac::built_in_permission_oid,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, EntityTrait, QueryFilter, Set, Statement, TransactionTrait, Value,
};
use serde_json::json;
use uuid::Uuid;

use super::{Seed, oauth_resource};
use crate::{
    application::error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, rbac::RbacErrorCode},
    },
    domain::openid_connect::{
        ApiScope, is_scope_pattern, model::claim::StandardScopes, scope_pattern_matches,
    },
    infrastructure::database::{
        audit, client_authorization_boundary,
        entity::{
            scope,
            scope::{Column as ScopeColumn, Entity as ScopeEntity},
        },
        repository::authorization_lifecycle,
    },
};

pub struct BuiltInScopeDefinition {
    pub code: &'static str,
    pub name: &'static str,
    pub name_zh_cn: &'static str,
    pub description: &'static str,
    pub description_zh_cn: &'static str,
}

pub const BUILT_IN_OPENID_CONNECT_SCOPES: &[BuiltInScopeDefinition] = &[
    BuiltInScopeDefinition {
        code: StandardScopes::OPENID,
        name: "OpenID",
        name_zh_cn: "OpenID",
        description: "Identifies your account so you can sign in to the application",
        description_zh_cn: "识别你的账户并登录应用",
    },
    BuiltInScopeDefinition {
        code: StandardScopes::PROFILE,
        name: "Profile",
        name_zh_cn: "个人资料",
        description: "Provides your basic profile information to the application",
        description_zh_cn: "向应用提供你的基本个人资料",
    },
    BuiltInScopeDefinition {
        code: StandardScopes::EMAIL,
        name: "Email",
        name_zh_cn: "邮箱",
        description: "Provides your email address and verification status to the application",
        description_zh_cn: "向应用提供你的邮箱地址和验证状态",
    },
    BuiltInScopeDefinition {
        code: StandardScopes::ADDRESS,
        name: "Address",
        name_zh_cn: "地址",
        description: "Provides your postal address to the application",
        description_zh_cn: "向应用提供你的邮寄地址",
    },
    BuiltInScopeDefinition {
        code: StandardScopes::PHONE,
        name: "Phone",
        name_zh_cn: "电话",
        description: "Provides your phone number and verification status to the application",
        description_zh_cn: "向应用提供你的电话号码和验证状态",
    },
    BuiltInScopeDefinition {
        code: StandardScopes::OFFLINE_ACCESS,
        name: "Offline Access",
        name_zh_cn: "离线访问",
        description: "Maintains authorized access while you are not using the application",
        description_zh_cn: "在你未使用应用时继续使用已授权的权限",
    },
    BuiltInScopeDefinition {
        code: ApiScope::USER_WRITE,
        name: "Write user profile",
        name_zh_cn: "修改用户资料",
        description: "Update your profile, account identifiers, and MFA settings",
        description_zh_cn: "修改个人资料、账户标识和多因素认证设置",
    },
    BuiltInScopeDefinition {
        code: ApiScope::USER_READ,
        name: "Read user profile",
        name_zh_cn: "查看用户资料",
        description: "Read your profile, groups, roles, permissions, and security status",
        description_zh_cn: "查看个人资料、用户组、角色、权限和安全状态",
    },
    BuiltInScopeDefinition {
        code: ApiScope::SESSION_REVOKE,
        name: "Revoke sessions",
        name_zh_cn: "撤销会话",
        description: "Enables ending sign-in sessions you no longer need",
        description_zh_cn: "结束不再需要的登录状态",
    },
    BuiltInScopeDefinition {
        code: ApiScope::SESSION_READ,
        name: "Read sessions",
        name_zh_cn: "查看会话",
        description: "Provides information about your sign-in sessions",
        description_zh_cn: "查看你的登录状态信息",
    },
    BuiltInScopeDefinition {
        code: ApiScope::PASSWORD_CHANGE,
        name: "Change password",
        name_zh_cn: "修改密码",
        description: "Allows you to change your password",
        description_zh_cn: "修改你的密码",
    },
];

/// Protocol and identity scopes are global, so they keep `resource_id` NULL.
/// Every business/API scope belongs to the reserved GraphQL resource.
pub(crate) fn is_protocol_scope_code(code: &str) -> bool {
    matches!(
        code,
        StandardScopes::OPENID
            | StandardScopes::PROFILE
            | StandardScopes::EMAIL
            | StandardScopes::ADDRESS
            | StandardScopes::PHONE
            | StandardScopes::OFFLINE_ACCESS
    )
}

pub(crate) fn builtin_scope_resource_id(code: &str, graphql_resource_oid: Uuid) -> Option<Uuid> {
    (!is_protocol_scope_code(code)).then_some(graphql_resource_oid)
}

/// Resolve a trusted built-in scope within its ownership boundary. A duplicate
/// API code registered under another resource is deliberately invisible here.
pub(crate) async fn find_builtin_scope_id(
    db: &impl ConnectionTrait,
    code: &str,
    graphql_resource_oid: Uuid,
) -> Result<Option<i64>, AppError> {
    let mut query = ScopeEntity::find().filter(ScopeColumn::Code.eq(code));
    query = match builtin_scope_resource_id(code, graphql_resource_oid) {
        Some(resource_id) => query.filter(ScopeColumn::ResourceId.eq(resource_id)),
        None => query.filter(ScopeColumn::ResourceId.is_null()),
    };
    Ok(query
        .one(db)
        .await
        .map_err(AppError::internal)?
        .filter(|row| row.built_in)
        .map(|row| row.id))
}

/// Every concrete built-in scope definition. Wildcard selectors are input
/// syntax only and are never persisted as `scope.code` rows.
fn trusted_concrete_scope_codes() -> impl Iterator<Item = &'static str> {
    BUILT_IN_OPENID_CONNECT_SCOPES
        .iter()
        .map(|definition| definition.code)
        .chain(ManagementScope::ALL.into_iter().map(|scope| scope.name()))
}

fn unresolved_scope_error(selector: &str) -> AppError {
    AppError::internal(DbErr::Custom(format!(
        "trusted scope selector {selector} has no concrete definitions"
    )))
}

/// Resolve exact codes and trusted selectors to concrete, resource-owned scope
/// IDs. `user.*`, `session.*` and `management.*` expand only against the
/// compiled catalog; duplicate codes under another resource never participate.
pub(crate) async fn resolve_builtin_scope_ids<S: AsRef<str>>(
    db: &impl ConnectionTrait,
    selectors: &[S],
    graphql_resource_oid: Uuid,
) -> Result<Vec<i64>, AppError> {
    let mut ids = Vec::new();
    for selector in selectors {
        let selector = selector.as_ref();
        if selector.contains('*') {
            if !is_scope_pattern(selector) {
                return Err(unresolved_scope_error(selector));
            }
            let mut matched = false;
            for code in trusted_concrete_scope_codes()
                .filter(|candidate| scope_pattern_matches(selector, candidate))
            {
                matched = true;
                let id = find_builtin_scope_id(db, code, graphql_resource_oid)
                    .await?
                    .ok_or_else(|| unresolved_scope_error(selector))?;
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            if !matched {
                return Err(unresolved_scope_error(selector));
            }
        } else {
            let id = find_builtin_scope_id(db, selector, graphql_resource_oid)
                .await?
                .ok_or_else(|| unresolved_scope_error(selector))?;
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    Ok(ids)
}

/// Presentation metadata is deliberately local to the seed and keyed by the
/// trusted enum. The 29 names themselves come only from `ManagementScope`.
pub(crate) fn management_name(scope: ManagementScope) -> &'static str {
    match scope {
        ManagementScope::UsersRead => "Read users",
        ManagementScope::UsersWrite => "Manage users",
        ManagementScope::SessionsRead => "Read sessions",
        ManagementScope::ClientsRead => "Read clients",
        ManagementScope::ClientsWrite => "Manage clients",
        ManagementScope::ClientsDelete => "Delete clients",
        ManagementScope::ClientCredentialsRead => "Read client credentials",
        ManagementScope::ClientCredentialsWrite => "Manage client credentials",
        ManagementScope::ClientCredentialsRevoke => "Revoke client credentials",
        ManagementScope::ResourcesRead => "Read resources",
        ManagementScope::ResourcesWrite => "Write resources",
        ManagementScope::ScopesRead => "Read scopes",
        ManagementScope::ScopesWrite => "Write scopes",
        ManagementScope::SettingsRead => "Read settings",
        ManagementScope::SettingsWrite => "Write settings",
        ManagementScope::KeysRead => "Read keys",
        ManagementScope::KeysWrite => "Manage keys",
        ManagementScope::KeysRevoke => "Revoke keys",
        ManagementScope::AuditRead => "Read audit events",
        ManagementScope::RolesRead => "Read roles",
        ManagementScope::RolesWrite => "Write roles",
        ManagementScope::RoleAssignmentsRead => "Read role assignments",
        ManagementScope::RoleAssignmentsWrite => "Write role assignments",
        ManagementScope::GroupsRead => "Read user groups",
        ManagementScope::GroupsWrite => "Manage user groups",
        ManagementScope::GroupsDelete => "Delete user groups",
        ManagementScope::GroupMembersRead => "Read group members",
        ManagementScope::GroupMembersWrite => "Manage group members",
        ManagementScope::PermissionDelegate => "Delegate permission",
    }
}

pub(crate) fn management_name_zh_cn(scope: ManagementScope) -> &'static str {
    match scope {
        ManagementScope::UsersRead => "读取用户",
        ManagementScope::UsersWrite => "管理用户",
        ManagementScope::SessionsRead => "读取登录会话",
        ManagementScope::ClientsRead => "读取客户端",
        ManagementScope::ClientsWrite => "管理客户端",
        ManagementScope::ClientsDelete => "删除客户端",
        ManagementScope::ClientCredentialsRead => "读取客户端凭据",
        ManagementScope::ClientCredentialsWrite => "管理客户端凭据",
        ManagementScope::ClientCredentialsRevoke => "撤销客户端凭据",
        ManagementScope::ResourcesRead => "读取 API 资源",
        ManagementScope::ResourcesWrite => "维护 API 资源",
        ManagementScope::ScopesRead => "读取 scope 目录",
        ManagementScope::ScopesWrite => "维护 scope 目录",
        ManagementScope::SettingsRead => "读取实例设置",
        ManagementScope::SettingsWrite => "维护实例设置",
        ManagementScope::KeysRead => "读取密钥",
        ManagementScope::KeysWrite => "管理密钥",
        ManagementScope::KeysRevoke => "撤销密钥",
        ManagementScope::AuditRead => "读取安全审计",
        ManagementScope::RolesRead => "读取角色",
        ManagementScope::RolesWrite => "维护角色",
        ManagementScope::RoleAssignmentsRead => "读取角色分配",
        ManagementScope::RoleAssignmentsWrite => "维护角色分配",
        ManagementScope::GroupsRead => "查看用户组",
        ManagementScope::GroupsWrite => "管理用户组",
        ManagementScope::GroupsDelete => "删除用户组",
        ManagementScope::GroupMembersRead => "查看组成员",
        ManagementScope::GroupMembersWrite => "管理组成员",
        ManagementScope::PermissionDelegate => "委派权限",
    }
}

pub(crate) fn management_description_zh_cn(scope: ManagementScope) -> &'static str {
    match scope {
        ManagementScope::UsersRead => "读取用户和用户管理详情",
        ManagementScope::UsersWrite => "创建、更新、启用、停用或解锁用户",
        ManagementScope::SessionsRead => "读取跨用户会话",
        ManagementScope::ClientsRead => "读取 OAuth 客户端配置",
        ManagementScope::ClientsWrite => "创建、更新、启用、停用客户端或分配客户端范围",
        ManagementScope::ClientsDelete => "删除 OAuth 客户端",
        ManagementScope::ClientCredentialsRead => "读取客户端凭据元数据",
        ManagementScope::ClientCredentialsWrite => "创建或轮换客户端凭据",
        ManagementScope::ClientCredentialsRevoke => "撤销客户端凭据",
        ManagementScope::ResourcesRead => "读取 API 资源",
        ManagementScope::ResourcesWrite => "创建、更新、启用或停用 API 资源",
        ManagementScope::ScopesRead => "读取 scope 目录",
        ManagementScope::ScopesWrite => "创建或更新非保留 scope",
        ManagementScope::SettingsRead => "读取实例设置",
        ManagementScope::SettingsWrite => "更新实例设置",
        ManagementScope::KeysRead => "读取签名密钥和数据加密密钥的元数据",
        ManagementScope::KeysWrite => "添加或轮换签名密钥与数据加密密钥",
        ManagementScope::KeysRevoke => "撤销签名密钥和数据加密密钥",
        ManagementScope::AuditRead => "读取安全审计事件",
        ManagementScope::RolesRead => "读取业务角色",
        ManagementScope::RolesWrite => "创建或更新业务角色及其权限",
        ManagementScope::RoleAssignmentsRead => "读取用户及用户组角色分配",
        ManagementScope::RoleAssignmentsWrite => "分配或撤销用户及用户组角色",
        ManagementScope::GroupsRead => "读取用户组",
        ManagementScope::GroupsWrite => "创建、更新、启用或停用用户组",
        ManagementScope::GroupsDelete => "删除用户组",
        ManagementScope::GroupMembersRead => "读取用户组成员",
        ManagementScope::GroupMembersWrite => "增加或移除用户组成员",
        ManagementScope::PermissionDelegate => "委派本人尚未持有的已登记权限",
    }
}

/// Reads every store that can retain a scope token. Rows from `scope.code`
/// carry the trusted built-in status so a custom
/// `management.*` row cannot be silently adopted. Reads only; no historical
/// grant is renamed, deleted or reinterpreted.
const COLLISION_SCAN_SQL: &str = r#"
WITH stored_scopes AS (
    SELECT 'scope.code'::text AS source,
           s.code::text AS token,
           s.built_in AS built_in
    FROM scope s
    UNION ALL
    SELECT 'client_scope', s.code, NULL::boolean
    FROM client_scope cs
    JOIN scope s ON s.id = cs.scope_id
    UNION ALL
    SELECT 'user_client_consent', s.code, NULL::boolean
    FROM user_client_consent c
    JOIN scope s ON s.id = c.scope_id
    UNION ALL
    SELECT 'client_authorization.scope', token, NULL::boolean
    FROM client_authorization ca
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(ca.data->>'scope', ''), '\s+') AS token
    WHERE ca.revoked_at IS NULL AND ca.expires_at > now()
    UNION ALL
    SELECT 'client_authorization.approved_scope', token, NULL::boolean
    FROM client_authorization ca
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(ca.data->>'approved_scope', ''), '\s+') AS token
    WHERE ca.revoked_at IS NULL AND ca.expires_at > now()
    UNION ALL
    SELECT 'client_authorization.request.scope', token, NULL::boolean
    FROM client_authorization ca
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(ca.data->'request'->>'scope', ''), '\s+') AS token
    WHERE ca.revoked_at IS NULL AND ca.expires_at > now()
    UNION ALL
    SELECT 'client_authorization.parameters.scope', token, NULL::boolean
    FROM client_authorization ca
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(ca.data->'parameters'->>'scope', ''), '\s+') AS token
    WHERE ca.revoked_at IS NULL AND ca.expires_at > now()
    UNION ALL
    SELECT 'client_authorization.approval.approved_scope', token, NULL::boolean
    FROM client_authorization ca
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(ca.data->'approval'->>'approved_scope', ''), '\s+') AS token
    WHERE ca.revoked_at IS NULL AND ca.expires_at > now()
)
SELECT source, token, built_in
FROM stored_scopes
WHERE token IS NOT NULL
  AND token <> ''
  AND token LIKE 'management.%'
ORDER BY source, token
"#;

pub struct BuiltInScopeSeed;

#[async_trait]
impl Seed for BuiltInScopeSeed {
    fn name(&self) -> &'static str {
        "built_in_scopes"
    }

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        ensure_built_in_scopes(db).await
    }
}

pub async fn ensure_built_in_scopes(db: &DatabaseConnection) -> Result<(), AppError> {
    let transaction = db.begin().await.map_err(AppError::internal)?;

    // Collision detection is deliberately before any write so a failure rolls
    // back the whole catalog refresh and `run_all` never proceeds to RBAC.
    ensure_no_reserved_scope_collisions(&transaction).await?;

    let graphql_resource_oid = oauth_resource::graphql_resource_oid(&transaction).await?;

    for definition in BUILT_IN_OPENID_CONNECT_SCOPES {
        upsert_scope(
            &transaction,
            ScopeUpsert {
                resource_id: builtin_scope_resource_id(definition.code, graphql_resource_oid),
                canonical_oid: None,
                code: definition.code,
                name: definition.name,
                name_zh_cn: definition.name_zh_cn,
                description: definition.description,
                description_zh_cn: definition.description_zh_cn,
            },
        )
        .await?;
    }

    for management_scope in ManagementScope::ALL {
        upsert_scope(
            &transaction,
            ScopeUpsert {
                resource_id: Some(graphql_resource_oid),
                canonical_oid: Some(built_in_permission_oid(management_scope).0),
                code: management_scope.name(),
                name: management_name(management_scope),
                name_zh_cn: management_name_zh_cn(management_scope),
                description: management_scope.description(),
                description_zh_cn: management_description_zh_cn(management_scope),
            },
        )
        .await?;
    }

    reconcile_non_management_built_in_scopes(&transaction, graphql_resource_oid).await?;

    transaction.commit().await.map_err(AppError::internal)?;
    Ok(())
}

async fn ensure_no_reserved_scope_collisions(db: &impl ConnectionTrait) -> Result<(), AppError> {
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            COLLISION_SCAN_SQL.to_owned(),
        ))
        .await
        .map_err(AppError::internal)?;

    for row in rows {
        let token = row
            .try_get::<String>("", "token")
            .map_err(AppError::internal)?;
        let source = row
            .try_get::<String>("", "source")
            .map_err(AppError::internal)?;
        let built_in = row
            .try_get::<Option<bool>>("", "built_in")
            .map_err(AppError::internal)?;
        if source == "scope.code" && built_in != Some(true) {
            // A historical custom row must never become a trusted built-in
            // entry merely because its spelling matches the catalog or uses a
            // retired reserved name.
            return Err(reserved_scope_error(token));
        }
        if RETIRED_MANAGEMENT_SCOPE_NAMES.contains(&token.as_str()) {
            // Removed by the RBAC seed together with its relations.
            continue;
        }
        if ManagementScope::from_name(&token).is_none() {
            return Err(reserved_scope_error(token));
        }
    }

    Ok(())
}

/// Exact 1-to-1 self-service built-in scope renames migrated before retiring
/// obsolete non-management built-in scope definitions.
const RENAMED_SELF_SERVICE_SCOPES: [(&str, &str); 2] = [
    ("account.read", ApiScope::USER_READ),
    ("account.update", ApiScope::USER_WRITE),
];

/// Reconcile non-management built-in scopes after an upgrade: migrate exact
/// 1-to-1 self-service renames onto the new rows, then retire any obsolete
/// built-in protocol or self-service scope rows.
async fn reconcile_non_management_built_in_scopes(
    transaction: &DatabaseTransaction,
    graphql_resource_oid: Uuid,
) -> Result<(), AppError> {
    let mut protocol_values: Vec<Value> = Vec::new();
    let mut self_service_values: Vec<Value> = Vec::new();
    for definition in BUILT_IN_OPENID_CONNECT_SCOPES {
        if is_protocol_scope_code(definition.code) {
            protocol_values.push(definition.code.into());
        } else {
            self_service_values.push(definition.code.into());
        }
    }

    let mut binds: Vec<Value> = vec![graphql_resource_oid.into()];
    let protocol_placeholders = (2..=protocol_values.len() + 1)
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let self_start = protocol_values.len() + 2;
    let self_placeholders = (self_start..self_start + self_service_values.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(", ");
    binds.extend(protocol_values);
    binds.extend(self_service_values);

    let obsolete_rows = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT id FROM \"scope\" \
                 WHERE built_in = true \
                   AND ( \
                     (resource_id IS NULL AND code NOT IN ({protocol_placeholders})) \
                     OR (resource_id = $1 AND code NOT LIKE 'management.%' AND code NOT IN ({self_placeholders})) \
                   ) \
                 ORDER BY id"
            ),
            binds,
        ))
        .await
        .map_err(AppError::internal)?;
    if obsolete_rows.is_empty() {
        return Ok(());
    }

    authorization_lifecycle::lock_owner_lifecycle(transaction)
        .await
        .map_err(AppError::internal)?;

    for (old_code, new_code) in RENAMED_SELF_SERVICE_SCOPES {
        let old_row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM \"scope\" WHERE built_in = true AND resource_id = $1 AND code = $2",
                [graphql_resource_oid.into(), old_code.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        let Some(old_row) = old_row else {
            continue;
        };
        let old_id = old_row
            .try_get::<i64>("", "id")
            .map_err(AppError::internal)?;
        let new_id = find_builtin_scope_id(transaction, new_code, graphql_resource_oid)
            .await?
            .ok_or_else(|| unresolved_scope_error(new_code))?;
        copy_scope_relations(transaction, old_id, new_id, false).await?;
    }

    let obsolete_ids: Vec<i64> = obsolete_rows
        .into_iter()
        .map(|row| row.try_get::<i64>("", "id"))
        .collect::<Result<_, _>>()
        .map_err(AppError::internal)?;
    retire_built_in_scopes(transaction, &obsolete_ids).await
}

/// Copy role, client and consent relations from `old_id` onto `new_id` before
/// `old_id` is retired. When `allow_client_granted` is `true`, existing
/// `client_granted` flags carry over (`true` wins over `false` on conflict);
/// when `false`, `client_granted` is forced to `false`.
pub(super) async fn copy_scope_relations(
    transaction: &DatabaseTransaction,
    old_id: i64,
    new_id: i64,
    allow_client_granted: bool,
) -> Result<(), AppError> {
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO role_permission(oid, role_id, scope_id, created_at) \
             SELECT gen_random_uuid(), role_id, $2, created_at \
             FROM role_permission \
             WHERE scope_id = $1 \
             ON CONFLICT (role_id, scope_id) DO NOTHING",
            [old_id.into(), new_id.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO client_scope(client_id, scope_id, client_granted, created_at) \
             SELECT client_id, $2, CASE WHEN $3 THEN client_granted ELSE false END, created_at \
             FROM client_scope \
             WHERE scope_id = $1 \
             ON CONFLICT (client_id, scope_id) DO UPDATE \
               SET client_granted = CASE \
                   WHEN $3 THEN client_scope.client_granted OR EXCLUDED.client_granted \
                   ELSE false \
               END",
            [old_id.into(), new_id.into(), allow_client_granted.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO user_client_consent(user_id, client_id, scope_id, approved_at) \
             SELECT user_id, client_id, $2, approved_at \
             FROM user_client_consent \
             WHERE scope_id = $1 \
             ON CONFLICT (user_id, client_id, scope_id) DO NOTHING",
            [old_id.into(), new_id.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Remove retired built-in scope rows cleanly: reconcile affected roles
/// (version rotation, affected-user authority withdrawal, semantic audit),
/// withdraw authorizations and rotate versions for affected clients, and delete
/// the obsolete scope rows.
pub(super) async fn retire_built_in_scopes(
    transaction: &DatabaseTransaction,
    obsolete_scope_ids: &[i64],
) -> Result<(), AppError> {
    if obsolete_scope_ids.is_empty() {
        return Ok(());
    }
    let scope_values: Vec<Value> = obsolete_scope_ids.iter().map(|id| (*id).into()).collect();
    let scope_placeholders = (1..=scope_values.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(", ");

    let affected_clients = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT DISTINCT c.id AS client_id, c.oid AS client_oid \
                 FROM client_scope cs \
                 JOIN client c ON c.id = cs.client_id \
                 WHERE cs.scope_id IN ({scope_placeholders}) \
                 ORDER BY c.id"
            ),
            scope_values.clone(),
        ))
        .await
        .map_err(AppError::internal)?;
    let mut client_ids: BTreeMap<i64, Uuid> = BTreeMap::new();
    for row in affected_clients {
        let client_id = row
            .try_get::<i64>("", "client_id")
            .map_err(AppError::internal)?;
        let client_oid = row
            .try_get::<Uuid>("", "client_oid")
            .map_err(AppError::internal)?;
        client_ids.insert(client_id, client_oid);
    }

    let roles = transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT DISTINCT r.id AS role_id, r.oid AS role_oid \
                 FROM role_permission rp \
                 JOIN \"role\" r ON r.id = rp.role_id \
                 WHERE rp.scope_id IN ({scope_placeholders}) \
                 ORDER BY r.id"
            ),
            scope_values.clone(),
        ))
        .await
        .map_err(AppError::internal)?;

    for row in roles {
        let role_id = row
            .try_get::<i64>("", "role_id")
            .map_err(AppError::internal)?;
        let role_oid = row
            .try_get::<Uuid>("", "role_oid")
            .map_err(AppError::internal)?;
        let mut values = vec![role_id.into()];
        values.extend(scope_values.iter().cloned());
        let shifted = (2..=scope_values.len() + 1)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(", ");
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "DELETE FROM role_permission \
                     WHERE role_id = $1 AND scope_id IN ({shifted})"
                ),
                values,
            ))
            .await
            .map_err(AppError::internal)?;
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
            role_oid,
        )
        .await
        .map_err(AppError::internal)?;
    }

    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("DELETE FROM \"scope\" WHERE built_in = true AND id IN ({scope_placeholders})"),
            scope_values,
        ))
        .await
        .map_err(AppError::internal)?;

    for (client_id, client_oid) in client_ids {
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE client SET version = gen_random_uuid(), updated_at = now() WHERE id = $1",
                [client_id.into()],
            ))
            .await
            .map_err(AppError::internal)?;
        client_authorization_boundary::withdraw_client_authorizations(transaction, client_id)
            .await
            .map_err(AppError::internal)?;
        audit::record(transaction, "client.update", "client", client_oid)
            .await
            .map_err(AppError::internal)?;
    }

    Ok(())
}

pub(super) async fn advance_users_affected_by_role(
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

fn reserved_scope_error(scope: String) -> AppError {
    AppError::from_code(AuthorizationErrorCode::ReservedManagementScope).with_param("scope", scope)
}

fn built_in_identity_conflict() -> AppError {
    AppError::from_code(RbacErrorCode::BuiltInIdentityConflict)
}

/// One built-in scope row as the seed expects it to be stored.
struct ScopeUpsert<'a> {
    resource_id: Option<Uuid>,
    /// Required stable `oid` when the scope has a canonical identity.
    canonical_oid: Option<Uuid>,
    code: &'a str,
    name: &'a str,
    name_zh_cn: &'a str,
    description: &'a str,
    description_zh_cn: &'a str,
}

async fn upsert_scope(db: &impl ConnectionTrait, row: ScopeUpsert<'_>) -> Result<(), AppError> {
    let ScopeUpsert {
        resource_id,
        canonical_oid,
        code,
        name,
        name_zh_cn,
        description,
        description_zh_cn,
    } = row;
    let names = json!({"en-US":name,"zh-CN":name_zh_cn});
    let descriptions = json!({"en-US":description,"zh-CN":description_zh_cn});
    let mut query = ScopeEntity::find().filter(ScopeColumn::Code.eq(code));
    query = match resource_id {
        Some(resource_id) => query.filter(ScopeColumn::ResourceId.eq(resource_id)),
        None => query.filter(ScopeColumn::ResourceId.is_null()),
    };
    let existing = query.one(db).await.map_err(AppError::internal)?;
    if let Some(existing) = existing {
        if !existing.built_in {
            return Err(reserved_scope_error(code.to_owned()));
        }
        if let Some(expected_oid) = canonical_oid
            && existing.oid != expected_oid
        {
            return Err(built_in_identity_conflict());
        }
        if existing.name == name
            && existing.names == names
            && existing.description == description
            && existing.descriptions == descriptions
            && existing.enabled
        {
            return Ok(());
        }
        let mut active: scope::ActiveModel = existing.into();
        active.name = Set(name.to_owned());
        active.names = Set(names);
        active.description = Set(description.to_owned());
        active.descriptions = Set(descriptions);
        active.enabled = Set(true);
        active.version = Set(Uuid::new_v4());
        active.updated_at = Set(Some(Utc::now().into()));
        active.update(db).await.map_err(AppError::internal)?;
        return Ok(());
    }
    scope::ActiveModel {
        oid: Set(canonical_oid.unwrap_or_else(Uuid::new_v4)),
        resource_id: Set(resource_id),
        code: Set(code.to_owned()),
        name: Set(name.to_owned()),
        names: Set(names),
        description: Set(description.to_owned()),
        descriptions: Set(descriptions),
        built_in: Set(true),
        enabled: Set(true),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}
