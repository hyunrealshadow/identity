use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "security_audit")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub oid: Uuid,
    pub occurred_at: DateTimeWithTimeZone,
    pub transaction_id: i64,
    pub resource_type: String,
    pub resource_oid: Uuid,
    pub subject_oid: Option<Uuid>,
    pub operation: String,
    pub credential_type: Option<String>,
    pub previous_status: Option<String>,
    pub status: Option<String>,
    pub actor_type: Option<String>,
    pub actor_oid: Option<Uuid>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_oid: Option<Uuid>,
    pub reason: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub event_kind: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
