//! Shared persistence for short-lived authentication challenges.
use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "authentication_challenge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    #[sea_orm(indexed)]
    pub user_id: i64,
    #[sea_orm(indexed)]
    pub login_id: Option<i64>,
    #[sea_orm(indexed)]
    pub session_id: Option<i64>,
    pub method: String,
    pub purpose: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub state: Json,
    #[sea_orm(indexed)]
    pub expires_at: DateTimeWithTimeZone,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_delete = "Cascade"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::login::Entity",
        from = "Column::LoginId",
        to = "super::login::Column::Id",
        on_delete = "Cascade"
    )]
    Login,
    #[sea_orm(
        belongs_to = "super::session::Entity",
        from = "Column::SessionId",
        to = "super::session::Column::Id",
        on_delete = "Cascade"
    )]
    Session,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
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
impl ActiveModelBehavior for ActiveModel {}
