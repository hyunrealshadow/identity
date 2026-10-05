//! Current SeaORM persistence entity.

use super::key_jwk::Entity as KeyJwkEntity;

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "key")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub oid: Uuid,
    pub r#type: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub data: Json,
    pub expires_at: DateTimeWithTimeZone,
    pub revoked_at: Option<DateTimeWithTimeZone>,
    pub rotated_from_oid: Option<Uuid>,
    pub rotated_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::key_jwk::Entity")]
    KeyJwk,
}

impl Related<KeyJwkEntity> for Entity {
    fn to() -> RelationDef {
        Relation::KeyJwk.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
