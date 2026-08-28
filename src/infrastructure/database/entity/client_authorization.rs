//! Current SeaORM persistence entity.

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "client_authorization")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    #[sea_orm(indexed)]
    pub client_id: i64,
    #[sea_orm(indexed)]
    pub r#type: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub data: Json,
    #[sea_orm(indexed)]
    pub expires_at: DateTimeWithTimeZone,
    pub completed_at: Option<DateTimeWithTimeZone>,
    pub revoked_at: Option<DateTimeWithTimeZone>,
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
    #[sea_orm(has_many = "super::login::Entity")]
    Login,
}

impl Related<super::client::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Client.def()
    }
}

impl Related<super::login::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Login.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
