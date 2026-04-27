use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
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
}

pub const BUILT_IN_OPENID_CONNECT_SCOPES: &[BuiltInScopeDefinition] = &[
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::OPENID,
        display_name: "OpenID",
        description: "Access your account identifier",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::PROFILE,
        display_name: "Profile",
        description: "Read your basic profile information",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::EMAIL,
        display_name: "Email",
        description: "Read your email address",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::ADDRESS,
        display_name: "Address",
        description: "Read your postal address",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::PHONE,
        display_name: "Phone",
        description: "Read your phone number",
    },
    BuiltInScopeDefinition {
        protocol: OPENID_CONNECT_PROTOCOL,
        name: StandardScopes::OFFLINE_ACCESS,
        display_name: "Offline Access",
        description: "Request refresh tokens for long-lived access",
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
                "offline_access"
            ]
        );
        assert!(
            BUILT_IN_OPENID_CONNECT_SCOPES
                .iter()
                .all(|scope| scope.protocol == OPENID_CONNECT_PROTOCOL)
        );
    }
}
