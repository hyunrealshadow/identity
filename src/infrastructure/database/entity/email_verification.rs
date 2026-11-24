//! The one outstanding email verification of an account.
use sea_orm::entity::prelude::*;

use super::user::Entity as UserEntity;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "email_verification")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    #[sea_orm(unique)]
    pub user_id: i64,
    pub email: String,
    pub email_normalized: String,
    pub current_email_normalized: String,
    #[sea_orm(unique)]
    pub token_digest: String,
    pub send_count: i32,
    pub window_started_at: DateTimeWithTimeZone,
    pub sent_at: DateTimeWithTimeZone,
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
}

impl Related<UserEntity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}
impl ActiveModelBehavior for ActiveModel {}
