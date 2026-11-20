use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub oid: Uuid,
    pub occurred_at: DateTimeWithTimeZone,
    pub category: String,
    pub action: String,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub actor_kind: String,
    pub actor_oid: Option<Uuid>,
    pub actor_label: Option<String>,
    pub target_kind: Option<String>,
    pub target_oid: Option<Uuid>,
    pub target_label: Option<String>,
    pub client_oid: Option<Uuid>,
    pub auth_methods: Option<Json>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub changes: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
