use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    domain::openid_connect::ApiScope,
    domain::openid_connect::model::claim::StandardScopes,
    infrastructure::database::entity::scope,
};

use super::Seed;

pub const OPENID_CONNECT_PROTOCOL: &str = "openid_connect";

pub struct BuiltInScopeDefinition {
    pub protocol: &'static str,
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub description_zh_cn: &'static str,
}

pub const BUILT_IN_OPENID_CONNECT_SCOPES: &[BuiltInScopeDefinition] = &[
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::OPENID,
        display_name: "OpenID",
        description: "Access your account identifier",
        description_zh_cn: "验证你的身份。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::PROFILE,
        display_name: "Profile",
        description: "Read your basic profile information",
        description_zh_cn: "查看你的基本个人资料。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::EMAIL,
        display_name: "Email",
        description: "Read your email address",
        description_zh_cn: "查看你的邮箱地址。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::ADDRESS,
        display_name: "Address",
        description: "Read your postal address",
        description_zh_cn: "查看你的邮寄地址。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::PHONE,
        display_name: "Phone",
        description: "Read your phone number",
        description_zh_cn: "查看你的电话号码。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::OFFLINE_ACCESS,
        display_name: "Offline Access",
        description: "Request refresh tokens for long-lived access",
        description_zh_cn: "在你未使用应用时保持访问权限。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::ACCOUNT,
        display_name: "Account",
        description: "Read and update your account",
        description_zh_cn: "读取和更新你的账户。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::ACCOUNT_UPDATE,
        display_name: "Update account",
        description: "Update your account profile",
        description_zh_cn: "更新你的账户资料。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::ACCOUNT_READ,
        display_name: "Read account",
        description: "Read your account profile",
        description_zh_cn: "读取你的账户资料。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::SESSION,
        display_name: "Sessions",
        description: "Read and revoke your sessions",
        description_zh_cn: "读取和撤销你的会话。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::SESSION_REVOKE,
        display_name: "Revoke sessions",
        description: "Revoke your sessions",
        description_zh_cn: "撤销你的会话。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::SESSION_READ,
        display_name: "Read sessions",
        description: "Read your sessions",
        description_zh_cn: "读取你的会话。",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::PASSWORD_CHANGE,
        display_name: "Change password",
        description: "Change your password after recent authentication",
        description_zh_cn: "在近期完成身份验证后修改你的密码。",
    },
];

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
    for definition in BUILT_IN_OPENID_CONNECT_SCOPES {
        let existing = scope::Entity::find()
            .filter(scope::Column::Protocol.eq(definition.protocol))
            .filter(scope::Column::Name.eq(definition.name))
            .one(db)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;

        if let Some(existing) = existing {
            let mut active: scope::ActiveModel = existing.into();
            active.display_name = Set(definition.display_name.to_string());
            active.description = Set(definition.description.to_string());
            active.descriptions = Set(serde_json::json!({
                "en-US": definition.description,
                "zh-CN": definition.description_zh_cn,
            }));
            active.built_in = Set(true);
            active.update(db).await.map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        } else {
            scope::ActiveModel {
                protocol: Set(definition.protocol.to_string()),
                name: Set(definition.name.to_string()),
                display_name: Set(definition.display_name.to_string()),
                description: Set(definition.description.to_string()),
                descriptions: Set(serde_json::json!({
                    "en-US": definition.description,
                    "zh-CN": definition.description_zh_cn,
                })),
                built_in: Set(true),
                ..Default::default()
            }
            .insert(db)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BUILT_IN_OPENID_CONNECT_SCOPES, OPENID_CONNECT_PROTOCOL};

    #[test]
    fn built_in_oidc_scopes_cover_standard_scope_catalog() {
        let names = BUILT_IN_OPENID_CONNECT_SCOPES
            .iter()
            .map(|scope| scope.name)
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
                "account",
                "account.update",
                "account.read",
                "session",
                "session.revoke",
                "session.read",
                "password.change",
            ]
        );
        assert!(
            BUILT_IN_OPENID_CONNECT_SCOPES
                .iter()
                .all(|scope| scope.protocol == OPENID_CONNECT_PROTOCOL)
        );
    }
}
