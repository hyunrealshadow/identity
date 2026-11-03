//! Current SeaORM persistence entity.

use super::{
    client::Entity as ClientEntity,
    client_openid_connect::{Entity as OidcClientEntity, Relation as ClientOpenIdConnectRelation},
};

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "client_openid_connect_credential")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    #[sea_orm(default_expr = "Expr::cust(\"gen_random_uuid()\")")]
    pub oid: Uuid,
    pub client_id: i64,
    pub r#type: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub data: Json,
    pub hint: String,
    pub expires_at: DateTimeWithTimeZone,
    pub revoked_at: Option<DateTimeWithTimeZone>,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::client_openid_connect::Entity",
        from = "Column::ClientId",
        to = "super::client_openid_connect::Column::ClientId",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    OpenIdConnectClient,
}

impl Related<OidcClientEntity> for Entity {
    fn to() -> RelationDef {
        Relation::OpenIdConnectClient.def()
    }
}

impl Related<ClientEntity> for Entity {
    fn to() -> RelationDef {
        ClientOpenIdConnectRelation::Client.def()
    }
    fn via() -> Option<RelationDef> {
        Some(Relation::OpenIdConnectClient.def())
    }
}

impl ActiveModelBehavior for ActiveModel {}
