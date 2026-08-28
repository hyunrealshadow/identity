//! Current SeaORM persistence entity.

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    pub name: String,
    #[sea_orm(unique)]
    pub name_normalized: String,
    pub email: String,
    #[sea_orm(unique)]
    pub email_normalized: String,
    #[sea_orm(default_value = false)]
    pub email_verified: bool,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub nickname: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zone_info: Option<String>,
    pub locale: Option<String>,
    #[sea_orm(column_type = "JsonBinary")]
    #[sea_orm(default_expr = "Expr::cust(\"'{}'::jsonb\")")]
    pub preferences: Json,
    pub address_formatted: Option<String>,
    pub address_street_address: Option<String>,
    pub address_locality: Option<String>,
    pub address_region: Option<String>,
    pub address_postal_code: Option<String>,
    pub address_country: Option<String>,
    #[sea_orm(default_value = 0)]
    pub failed_attempts: i32,
    #[sea_orm(default_value = true)]
    pub enabled: bool,
    #[sea_orm(default_value = false)]
    pub locked: bool,
    pub locked_until: Option<DateTimeWithTimeZone>,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::login::Entity")]
    Login,
    #[sea_orm(has_many = "super::session::Entity")]
    Session,
    #[sea_orm(has_many = "super::user_credential::Entity")]
    UserCredential,
}

impl Related<super::login::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Login.def()
    }
}

impl Related<super::session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}

impl Related<super::user_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserCredential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
