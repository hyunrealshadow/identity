use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "role")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub oid: Uuid,
    pub name: String,
    pub description: String,
    #[sea_orm(default_expr = "Expr::cust(\"'{}'::jsonb\")")]
    pub names: Json,
    #[sea_orm(default_expr = "Expr::cust(\"'{}'::jsonb\")")]
    pub descriptions: Json,
    #[sea_orm(default_value = false)]
    pub built_in: bool,
    #[sea_orm(default_value = true)]
    pub enabled: bool,
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub version: Uuid,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
