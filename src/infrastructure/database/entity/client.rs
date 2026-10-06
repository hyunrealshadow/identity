//! Current SeaORM persistence entity.

use super::{
    client_authorization::Entity as ClientAuthorizationEntity,
    client_openid_connect::Entity as ClientOpenidConnectEntity,
    client_openid_connect_cors_origin::Entity as ClientOpenidConnectCorsOriginEntity,
    client_openid_connect_credential::Entity as ClientOpenidConnectCredentialEntity,
    client_openid_connect_platform::Entity as ClientOpenidConnectPlatformEntity,
    client_scope::Entity as ClientScopeEntity, login::Entity as LoginEntity,
    user_client_consent::Entity as UserClientConsentEntity,
};

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "client")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    pub protocol: String,
    pub name: String,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub names: Option<Json>,
    pub description: Option<String>,
    #[sea_orm(default_value = false)]
    pub built_in: bool,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::client_authorization::Entity")]
    ClientAuthorization,
    #[sea_orm(has_one = "super::client_openid_connect::Entity")]
    ClientOpenIdConnect,
    #[sea_orm(has_many = "super::client_openid_connect_cors_origin::Entity")]
    ClientOpenIdConnectCorsOrigin,
    #[sea_orm(has_many = "super::client_openid_connect_credential::Entity")]
    ClientOpenIdConnectCredential,
    #[sea_orm(has_many = "super::client_openid_connect_platform::Entity")]
    ClientOpenIdConnectPlatform,
    #[sea_orm(has_many = "super::client_scope::Entity")]
    ClientScope,
    #[sea_orm(has_many = "super::login::Entity")]
    Login,
    #[sea_orm(has_many = "super::user_client_consent::Entity")]
    UserClientConsent,
}

impl Related<ClientAuthorizationEntity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientAuthorization.def()
    }
}

impl Related<ClientOpenidConnectEntity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientOpenIdConnect.def()
    }
}

impl Related<ClientOpenidConnectCorsOriginEntity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientOpenIdConnectCorsOrigin.def()
    }
}

impl Related<ClientOpenidConnectCredentialEntity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientOpenIdConnectCredential.def()
    }
}

impl Related<ClientOpenidConnectPlatformEntity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientOpenIdConnectPlatform.def()
    }
}

impl Related<ClientScopeEntity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientScope.def()
    }
}

impl Related<LoginEntity> for Entity {
    fn to() -> RelationDef {
        Relation::Login.def()
    }
}

impl Related<UserClientConsentEntity> for Entity {
    fn to() -> RelationDef {
        Relation::UserClientConsent.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
