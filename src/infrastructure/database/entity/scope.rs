//! Current SeaORM persistence entity.

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "scope")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    #[sea_orm(unique_key = "idx_scope_protocol_name")]
    pub protocol: String,
    #[sea_orm(unique_key = "idx_scope_protocol_name")]
    pub name: String,
    pub display_name: String,
    pub description: String,
    #[sea_orm(default_value = false)]
    pub built_in: bool,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::client_scope::Entity")]
    ClientScope,
}

impl Related<super::client_scope::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClientScope.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
