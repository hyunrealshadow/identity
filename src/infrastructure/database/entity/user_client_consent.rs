//! Persisted user approval for one scope requested by one client.

use sea_orm::entity::prelude::*;

#[sea_orm::compact_model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_client_consent")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique_key = "idx_user_client_consent_unique_scope_id")]
    pub user_id: i64,
    #[sea_orm(unique_key = "idx_user_client_consent_unique_scope_id")]
    pub client_id: i64,
    #[sea_orm(unique_key = "idx_user_client_consent_unique_scope_id")]
    pub scope_id: i64,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub approved_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::client::Entity",
        from = "Column::ClientId",
        to = "super::client::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Client,
    #[sea_orm(
        belongs_to = "super::scope::Entity",
        from = "Column::ScopeId",
        to = "super::scope::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Scope,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::client::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Client.def()
    }
}

impl Related<super::scope::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Scope.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
