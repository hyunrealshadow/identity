use async_trait::async_trait;
use chrono::Utc;
use identity_domain::{authorization::catalog::ManagementScope, rbac::built_in_permission_oid};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    QueryFilter, Set, Statement, TransactionTrait,
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
    infrastructure::database::entity::scope,
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
        code: ApiScope::ACCOUNT_UPDATE,
        name: "Update account",
        name_zh_cn: "修改账户",
        description: "Enables account profile management",
        description_zh_cn: "管理你的账户资料",
    },
    BuiltInScopeDefinition {
        code: ApiScope::ACCOUNT_READ,
        name: "Read account",
        name_zh_cn: "查看账户",
        description: "Provides access to your account profile",
        description_zh_cn: "查看你的账户资料",
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
    let mut query = scope::Entity::find().filter(scope::Column::Code.eq(code));
    query = match builtin_scope_resource_id(code, graphql_resource_oid) {
        Some(resource_id) => query.filter(scope::Column::ResourceId.eq(resource_id)),
        None => query.filter(scope::Column::ResourceId.is_null()),
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
    AppError::internal(sea_orm::DbErr::Custom(format!(
        "trusted scope selector {selector} has no concrete definitions"
    )))
}

/// Resolve exact codes and trusted selectors to concrete, resource-owned scope
/// IDs. `account.*`, `session.*` and `management.*` expand only against the
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
                .filter(|candidate| scope_pattern_matches(selector, *candidate))
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
/// trusted enum. The 36 names themselves come only from `ManagementScope`.
pub(crate) fn management_name(scope: ManagementScope) -> &'static str {
    match scope {
        ManagementScope::UsersRead => "Read users",
        ManagementScope::UsersCreate => "Create users",
        ManagementScope::UsersUpdate => "Update users",
        ManagementScope::UsersState => "Change user state",
        ManagementScope::UsersRevokeAccess => "Revoke user access",
        ManagementScope::SessionsRead => "Read sessions",
        ManagementScope::SessionsRevoke => "Revoke sessions",
        ManagementScope::CredentialsRead => "Read credentials",
        ManagementScope::CredentialsRevoke => "Revoke credentials",
        ManagementScope::CredentialsReset => "Reset MFA",
        ManagementScope::ClientsRead => "Read clients",
        ManagementScope::ClientsCreate => "Create clients",
        ManagementScope::ClientsUpdate => "Update clients",
        ManagementScope::ClientsState => "Change client state",
        ManagementScope::ClientsScopes => "Assign client scopes",
        ManagementScope::ClientCredentialsRead => "Read client credentials",
        ManagementScope::ClientCredentialsCreate => "Create client credentials",
        ManagementScope::ClientCredentialsRotate => "Rotate client credentials",
        ManagementScope::ClientCredentialsRevoke => "Revoke client credentials",
        ManagementScope::ResourcesRead => "Read resources",
        ManagementScope::ResourcesWrite => "Write resources",
        ManagementScope::ScopesRead => "Read scopes",
        ManagementScope::ScopesWrite => "Write scopes",
        ManagementScope::AdministratorsRead => "Read administrators",
        ManagementScope::AdministratorsWrite => "Write administrators",
        ManagementScope::ClientGrantsRead => "Read client grants",
        ManagementScope::ClientGrantsWrite => "Write client grants",
        ManagementScope::SettingsRead => "Read settings",
        ManagementScope::SettingsWrite => "Write settings",
        ManagementScope::AuditRead => "Read audit events",
        ManagementScope::PermissionRead => "Read permission",
        ManagementScope::PermissionWrite => "Write permission",
        ManagementScope::RolesRead => "Read roles",
        ManagementScope::RolesWrite => "Write roles",
        ManagementScope::RoleAssignmentsRead => "Read role assignments",
        ManagementScope::RoleAssignmentsWrite => "Write role assignments",
        ManagementScope::GroupsRead => "Read user groups",
        ManagementScope::GroupsWrite => "Manage user groups",
        ManagementScope::GroupMembershipsRead => "Read group members",
        ManagementScope::GroupMembershipsWrite => "Manage group members",
        ManagementScope::GroupRolesRead => "Read group roles",
        ManagementScope::GroupRolesWrite => "Manage group roles",
        ManagementScope::PermissionDelegate => "Delegate permission",
    }
}

#[allow(unreachable_patterns)]
pub(crate) fn management_name_zh_cn(scope: ManagementScope) -> &'static str {
    match scope {
        ManagementScope::UsersRead => "读取用户",
        ManagementScope::UsersCreate => "创建用户",
        ManagementScope::UsersUpdate => "更新用户",
        ManagementScope::UsersState => "变更用户状态",
        ManagementScope::UsersRevokeAccess => "撤销用户访问",
        ManagementScope::SessionsRead => "读取登录会话",
        ManagementScope::SessionsRevoke => "撤销登录会话",
        ManagementScope::CredentialsRead => "读取认证凭证",
        ManagementScope::CredentialsRevoke => "撤销认证凭证",
        ManagementScope::CredentialsReset => "重置多因素认证",
        ManagementScope::ClientsRead => "读取客户端",
        ManagementScope::ClientsCreate => "创建客户端",
        ManagementScope::ClientsUpdate => "更新客户端",
        ManagementScope::ClientsState => "变更客户端状态",
        ManagementScope::ClientsScopes => "分配客户端范围",
        ManagementScope::ClientCredentialsRead => "读取客户端凭据",
        ManagementScope::ClientCredentialsCreate => "创建客户端凭据",
        ManagementScope::ClientCredentialsRotate => "轮换客户端凭据",
        ManagementScope::ClientCredentialsRevoke => "撤销客户端凭据",
        ManagementScope::ResourcesRead => "读取 API 资源",
        ManagementScope::ResourcesWrite => "维护 API 资源",
        ManagementScope::ScopesRead => "读取 scope 目录",
        ManagementScope::ScopesWrite => "维护 scope 目录",
        ManagementScope::AdministratorsRead => "读取管理员绑定",
        ManagementScope::AdministratorsWrite => "维护管理员绑定",
        ManagementScope::ClientGrantsRead => "读取客户端管理授权",
        ManagementScope::ClientGrantsWrite => "维护客户端管理授权",
        ManagementScope::SettingsRead => "读取安全设置",
        ManagementScope::SettingsWrite => "维护安全设置",
        ManagementScope::AuditRead => "读取安全审计",
        ManagementScope::PermissionRead => "读取权限",
        ManagementScope::PermissionWrite => "维护权限",
        ManagementScope::RolesRead => "读取角色",
        ManagementScope::RolesWrite => "维护角色",
        ManagementScope::RoleAssignmentsRead => "读取角色分配",
        ManagementScope::RoleAssignmentsWrite => "维护角色分配",
        ManagementScope::GroupsRead => "查看用户组",
        ManagementScope::GroupsWrite => "管理用户组",
        ManagementScope::GroupMembershipsRead => "查看组成员",
        ManagementScope::GroupMembershipsWrite => "管理组成员",
        ManagementScope::GroupRolesRead => "查看用户组角色",
        ManagementScope::GroupRolesWrite => "管理用户组角色",
        ManagementScope::PermissionDelegate => "委派权限",
    }
}

pub(crate) fn management_description_zh_cn(scope: ManagementScope) -> &'static str {
    match scope {
        ManagementScope::UsersRead => "读取用户和用户管理详情",
        ManagementScope::UsersCreate => "创建用户",
        ManagementScope::UsersUpdate => "更新用户资料和登录标识",
        ManagementScope::UsersState => "启用、停用或解锁用户",
        ManagementScope::UsersRevokeAccess => "撤销用户的会话和其他访问",
        ManagementScope::SessionsRead => "读取跨用户会话",
        ManagementScope::SessionsRevoke => "撤销跨用户会话",
        ManagementScope::CredentialsRead => "读取凭证和通行密钥元数据",
        ManagementScope::CredentialsRevoke => "撤销其他用户的凭证",
        ManagementScope::CredentialsReset => "重置其他用户的多因素认证",
        ManagementScope::ClientsRead => "读取 OAuth 客户端配置",
        ManagementScope::ClientsCreate => "创建 OAuth 客户端",
        ManagementScope::ClientsUpdate => "更新 OAuth 客户端配置",
        ManagementScope::ClientsState => "启用或停用 OAuth 客户端",
        ManagementScope::ClientsScopes => "向 OAuth 客户端分配非保留 scope",
        ManagementScope::ClientCredentialsRead => "读取客户端凭据元数据",
        ManagementScope::ClientCredentialsCreate => "创建客户端凭据",
        ManagementScope::ClientCredentialsRotate => "轮换客户端凭据",
        ManagementScope::ClientCredentialsRevoke => "撤销客户端凭据",
        ManagementScope::ResourcesRead => "读取 API 资源",
        ManagementScope::ResourcesWrite => "创建、更新、启用或停用 API 资源",
        ManagementScope::ScopesRead => "读取 scope 目录",
        ManagementScope::ScopesWrite => "创建或更新非保留 scope",
        ManagementScope::AdministratorsRead => "读取管理员绑定",
        ManagementScope::AdministratorsWrite => "分配或变更管理员绑定",
        ManagementScope::ClientGrantsRead => "读取客户端管理授权",
        ManagementScope::ClientGrantsWrite => "设置或撤销客户端管理授权",
        ManagementScope::SettingsRead => "读取安全相关设置",
        ManagementScope::SettingsWrite => "更新安全相关设置",
        ManagementScope::AuditRead => "读取安全审计事件",
        ManagementScope::PermissionRead => "读取权限目录",
        ManagementScope::PermissionWrite => "创建或更新自定义权限",
        ManagementScope::RolesRead => "读取业务角色",
        ManagementScope::RolesWrite => "创建或更新业务角色及其权限",
        ManagementScope::RoleAssignmentsRead => "读取用户业务角色分配",
        ManagementScope::RoleAssignmentsWrite => "分配或撤销用户业务角色",
        ManagementScope::GroupsRead => "读取用户组",
        ManagementScope::GroupsWrite => "创建、更新或停用用户组",
        ManagementScope::GroupMembershipsRead => "读取用户组成员",
        ManagementScope::GroupMembershipsWrite => "增加或移除用户组成员",
        ManagementScope::GroupRolesRead => "读取用户组角色",
        ManagementScope::GroupRolesWrite => "分配或撤销用户组角色",
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
            builtin_scope_resource_id(definition.code, graphql_resource_oid),
            None,
            definition.code,
            definition.name,
            definition.name_zh_cn,
            definition.description,
            definition.description_zh_cn,
        )
        .await?;
    }

    for management_scope in ManagementScope::ALL {
        upsert_scope(
            &transaction,
            Some(graphql_resource_oid),
            Some(built_in_permission_oid(management_scope).0),
            management_scope.name(),
            management_name(management_scope),
            management_name_zh_cn(management_scope),
            management_scope.description(),
            management_description_zh_cn(management_scope),
        )
        .await?;
    }

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
        if ManagementScope::from_name(&token).is_none() {
            return Err(reserved_scope_error(token));
        }

        let source = row
            .try_get::<String>("", "source")
            .map_err(AppError::internal)?;
        if source != "scope.code" {
            // An exact trusted name already stored in a historical grant is
            // retained as-is. Reinterpreting or rewriting it is out of scope.
            continue;
        }

        let built_in = row
            .try_get::<Option<bool>>("", "built_in")
            .map_err(AppError::internal)?;
        if built_in != Some(true) {
            // A historical custom row must never become a trusted built-in
            // entry merely because its spelling matches the catalog.
            return Err(reserved_scope_error(token));
        }
    }

    Ok(())
}

fn reserved_scope_error(scope: String) -> AppError {
    AppError::from_code(AuthorizationErrorCode::ReservedManagementScope).with_param("scope", scope)
}

fn built_in_identity_conflict() -> AppError {
    AppError::from_code(RbacErrorCode::BuiltInIdentityConflict)
}

async fn upsert_scope(
    db: &impl ConnectionTrait,
    resource_id: Option<Uuid>,
    canonical_oid: Option<Uuid>,
    code: &str,
    name: &str,
    name_zh_cn: &str,
    description: &str,
    description_zh_cn: &str,
) -> Result<(), AppError> {
    let names = json!({"en-US":name,"zh-CN":name_zh_cn});
    let descriptions = json!({"en-US":description,"zh-CN":description_zh_cn});
    let mut query = scope::Entity::find().filter(scope::Column::Code.eq(code));
    query = match resource_id {
        Some(resource_id) => query.filter(scope::Column::ResourceId.eq(resource_id)),
        None => query.filter(scope::Column::ResourceId.is_null()),
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
        {
            return Ok(());
        }
        let mut active: scope::ActiveModel = existing.into();
        active.name = Set(name.to_owned());
        active.names = Set(names);
        active.description = Set(description.to_owned());
        active.descriptions = Set(descriptions);
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
