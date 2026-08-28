//! Current SeaORM persistence entity.

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "login")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    #[sea_orm(indexed)]
    pub client_id: i64,
    #[sea_orm(indexed)]
    pub client_authorization_id: i64,
    #[sea_orm(indexed)]
    pub session_id: Option<i64>,
    #[sea_orm(indexed)]
    pub user_id: Option<i64>,
    #[sea_orm(indexed)]
    pub status: String,
    pub failure_reason: Option<String>,
    #[sea_orm(default_value = 0)]
    pub failed_attempts: i32,
    pub acr: Option<String>,
    pub requested_acr: Option<String>,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::client::Entity",
        from = "Column::ClientId",
        to = "super::client::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Client,
    #[sea_orm(
        belongs_to = "super::client_authorization::Entity",
        from = "Column::ClientAuthorizationId",
        to = "super::client_authorization::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    ClientAuthorization,
    #[sea_orm(
        belongs_to = "super::session::Entity",
        from = "Column::SessionId",
        to = "super::session::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    Session,
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::client::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Client.def()
    }
}

impl Related<super::client_authorization::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientAuthorization.def()
    }
}

impl Related<super::session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
