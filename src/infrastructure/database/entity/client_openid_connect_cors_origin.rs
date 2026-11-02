//! Materialized CORS origins for OpenID Connect clients.

use super::client::Entity as ClientEntity;
use super::client_openid_connect::Entity as OidcClientEntity;

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "client_openid_connect_cors_origin")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique_key = "idx_client_openid_connect_cors_origin_client_id_origin")]
    pub client_id: i64,
    #[sea_orm(
        unique_key = "idx_client_openid_connect_cors_origin_client_id_origin",
        column_type = "Text"
    )]
    pub origin: String,
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
        super::client_openid_connect::Relation::Client.def()
    }
    fn via() -> Option<RelationDef> {
        Some(Relation::OpenIdConnectClient.def())
    }
}

impl ActiveModelBehavior for ActiveModel {}
