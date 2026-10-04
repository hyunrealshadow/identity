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
        description: "Identifies your account so you can sign in to the application",
        description_zh_cn: "用于识别你的账户并登录应用",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::PROFILE,
        display_name: "Profile",
        description: "Provides your basic profile information to the application",
        description_zh_cn: "用于向应用提供你的基本个人资料",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::EMAIL,
        display_name: "Email",
        description: "Provides your email address and verification status to the application",
        description_zh_cn: "用于向应用提供你的邮箱地址和验证状态",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::ADDRESS,
        display_name: "Address",
        description: "Provides your postal address to the application",
        description_zh_cn: "用于向应用提供你的邮寄地址",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::PHONE,
        display_name: "Phone",
        description: "Provides your phone number and verification status to the application",
        description_zh_cn: "用于向应用提供你的电话号码和验证状态",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::OFFLINE_ACCESS,
        display_name: "Offline Access",
        description: "Maintains authorized access while you are not using the application",
        description_zh_cn: "用于在你未使用应用时继续使用已授权的权限",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::ACCOUNT,
        display_name: "Account",
        description: "Enables account profile viewing and management",
        description_zh_cn: "用于查看和管理你的账户资料",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::ACCOUNT_UPDATE,
        display_name: "Update account",
        description: "Enables account profile management",
        description_zh_cn: "用于管理你的账户资料",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::ACCOUNT_READ,
        display_name: "Read account",
        description: "Provides access to your account profile",
        description_zh_cn: "用于查看你的账户资料",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::SESSION,
        display_name: "Sessions",
        description: "Enables viewing and managing your sign-in sessions",
        description_zh_cn: "用于查看和管理你的登录状态",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::SESSION_REVOKE,
        display_name: "Revoke sessions",
        description: "Enables ending sign-in sessions you no longer need",
        description_zh_cn: "用于结束不再需要的登录状态",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::SESSION_READ,
        display_name: "Read sessions",
        description: "Provides information about your sign-in sessions",
        description_zh_cn: "用于查看你的登录状态信息",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: ApiScope::PASSWORD_CHANGE,
        display_name: "Change password",
        description: "Allows you to change your password",
        description_zh_cn: "用于修改你的密码",
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
