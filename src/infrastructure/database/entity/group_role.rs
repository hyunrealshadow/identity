use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "group_role")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub oid: Uuid,
    pub group_id: i64,
    pub role_id: i64,
    pub granted_by_user_id: Option<i64>,
    pub reason: String,
    #[sea_orm(default_value = true)]
    pub enabled: bool,
    pub revoked_at: Option<DateTimeWithTimeZone>,
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub version: Uuid,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
