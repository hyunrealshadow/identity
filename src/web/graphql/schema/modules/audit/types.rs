use async_graphql::{Context, Enum, ID, Object, Result as GraphqlResult};
use chrono::{DateTime, Utc};
use identity_application::{authorization::ManagementTarget, client::ClientRecord};
use identity_domain::{
    audit::{
        AuditEvent, AuditEventOid, AuditEventOrder as DomainAuditEventOrder,
        AuditEventOrderDirection, AuditEventOrderField,
    },
    authorization::ManagementScope,
    global_id::{GlobalId, kind},
    user::{User, UserOid},
};
use uuid::Uuid;

use super::super::{
    account::UserNode,
    client::{self, types::ClientNode},
    resource::support::decode_oid,
    user,
};
use crate::graphql::schema::{
    access::access, authorization::request_context, error::app_error,
    management_guard::ManagementGuard,
};

pub(crate) use identity_domain::global_id::kind::AuditEvent as AuditEventGlobalId;

pub(crate) fn audit_event_global_id(oid: AuditEventOid) -> ID {
    ID(GlobalId::<AuditEventGlobalId>::new(oid.as_uuid()).encode())
}

pub(crate) fn decode_audit_event_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<AuditEventOid> {
    decode_oid::<AuditEventGlobalId>(ctx, id).map(AuditEventOid::from_uuid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum AuditEventOrder {
    #[graphql(name = "OCCURRED_AT_ASC")]
    OccurredAtAsc,
    #[graphql(name = "OCCURRED_AT_DESC")]
    OccurredAtDesc,
}

impl AuditEventOrder {
    pub(crate) const fn default_order() -> Self {
        Self::OccurredAtDesc
    }
}

impl From<AuditEventOrder> for DomainAuditEventOrder {
    fn from(value: AuditEventOrder) -> Self {
        let direction = match value {
            AuditEventOrder::OccurredAtAsc => AuditEventOrderDirection::Asc,
            AuditEventOrder::OccurredAtDesc => AuditEventOrderDirection::Desc,
        };
        Self {
            field: AuditEventOrderField::OccurredAt,
            direction,
        }
    }
}

pub(crate) struct AuditEventNode {
    id: ID,
    event: AuditEvent,
    preloaded_user: Option<User>,
    preloaded_user_loaded: bool,
    preloaded_client: Option<ClientRecord>,
    preloaded_client_loaded: bool,
}

impl AuditEventNode {
    pub(crate) fn new(event: AuditEvent) -> Self {
        Self {
            id: audit_event_global_id(event.oid),
            event,
            preloaded_user: None,
            preloaded_user_loaded: false,
            preloaded_client: None,
            preloaded_client_loaded: false,
        }
    }

    pub(crate) fn with_preloaded_actors(
        event: AuditEvent,
        preloaded_user: Option<User>,
        preloaded_user_loaded: bool,
        preloaded_client: Option<ClientRecord>,
        preloaded_client_loaded: bool,
    ) -> Self {
        Self {
            id: audit_event_global_id(event.oid),
            event,
            preloaded_user,
            preloaded_user_loaded,
            preloaded_client,
            preloaded_client_loaded,
        }
    }
}

#[Object(name = "AuditEvent")]
impl AuditEventNode {
    #[graphql(complexity = 0)]
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    #[graphql(complexity = 0)]
    async fn occurred_at(&self) -> DateTime<Utc> {
        self.event.occurred_at
    }

    #[graphql(complexity = 0)]
    async fn transaction_id(&self) -> String {
        self.event.transaction_id.to_string()
    }

    #[graphql(complexity = 0)]
    async fn action(&self) -> Option<&str> {
        self.event.action.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn operation(&self) -> &str {
        &self.event.operation
    }

    #[graphql(complexity = 0)]
    async fn event_kind(&self) -> Option<&str> {
        self.event.event_kind.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn actor_type(&self) -> Option<&str> {
        self.event.actor_type.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn actor_oid(&self) -> Option<String> {
        self.event.actor_oid.map(|oid| oid.to_string())
    }

    #[graphql(complexity = 0)]
    async fn actor_global_id(&self) -> Option<ID> {
        match (self.event.actor_type.as_deref(), self.event.actor_oid) {
            (Some(entity_type), Some(oid)) => global_id_for_entity_type(entity_type, oid),
            _ => None,
        }
    }

    #[graphql(complexity = 0)]
    async fn target_type(&self) -> Option<&str> {
        self.event.target_type.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn target_oid(&self) -> Option<String> {
        self.event.target_oid.map(|oid| oid.to_string())
    }

    #[graphql(complexity = 0)]
    async fn target_global_id(&self) -> Option<ID> {
        match (self.event.target_type.as_deref(), self.event.target_oid) {
            (Some(entity_type), Some(oid)) => global_id_for_entity_type(entity_type, oid),
            _ => None,
        }
    }

    #[graphql(complexity = 0)]
    async fn resource_type(&self) -> &str {
        &self.event.resource_type
    }

    #[graphql(complexity = 0)]
    async fn resource_oid(&self) -> String {
        self.event.resource_oid.to_string()
    }

    #[graphql(complexity = 0)]
    async fn resource_global_id(&self) -> Option<ID> {
        global_id_for_entity_type(&self.event.resource_type, self.event.resource_oid)
    }

    #[graphql(complexity = 0)]
    async fn subject_oid(&self) -> Option<String> {
        self.event.subject_oid.map(|oid| oid.to_string())
    }

    #[graphql(complexity = 0)]
    async fn subject_global_id(&self) -> Option<ID> {
        self.event
            .subject_oid
            .filter(|oid| !oid.is_nil())
            .map(|oid| ID(GlobalId::<kind::User>::new(oid).encode()))
    }

    #[graphql(complexity = 0)]
    async fn status(&self) -> Option<&str> {
        self.event.status.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn previous_status(&self) -> Option<&str> {
        self.event.previous_status.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn credential_type(&self) -> Option<&str> {
        self.event.credential_type.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn reason(&self) -> Option<&str> {
        self.event.reason.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn request_id(&self) -> Option<&str> {
        self.event.request_id.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn trace_id(&self) -> Option<&str> {
        self.event.trace_id.as_deref()
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn actor_user(&self, ctx: &Context<'_>) -> GraphqlResult<Option<UserNode>> {
        if self.event.actor_type.as_deref() != Some("user") {
            return Ok(None);
        }
        let Some(actor_oid) = self.event.actor_oid.filter(|oid| !oid.is_nil()) else {
            return Ok(None);
        };
        if self.preloaded_user_loaded {
            return Ok(self.preloaded_user.clone().map(UserNode::managed));
        }
        let request = request_context(ctx)?;
        let user = user::integration::find_user(request, UserOid(actor_oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(user.map(UserNode::managed))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead))
    )]
    async fn actor_client(&self, ctx: &Context<'_>) -> GraphqlResult<Option<ClientNode>> {
        if self.event.actor_type.as_deref() != Some("client") {
            return Ok(None);
        }
        let Some(actor_oid) = self.event.actor_oid.filter(|oid| !oid.is_nil()) else {
            return Ok(None);
        };
        if self.preloaded_client_loaded {
            return Ok(self.preloaded_client.clone().map(ClientNode::new));
        }
        let request = request_context(ctx)?;
        let client = client::integration::find_client(request, actor_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(client.map(ClientNode::new))
    }
}

fn global_id_for_entity_type(entity_type: &str, oid: Uuid) -> Option<ID> {
    if oid.is_nil() {
        return None;
    }
    let encoded = match entity_type {
        "user" => GlobalId::<kind::User>::new(oid).encode(),
        "client" => GlobalId::<kind::Client>::new(oid).encode(),
        "resource" => GlobalId::<kind::Resource>::new(oid).encode(),
        "scope" => GlobalId::<kind::Scope>::new(oid).encode(),
        "role" => GlobalId::<kind::Role>::new(oid).encode(),
        "user_group" => GlobalId::<kind::Group>::new(oid).encode(),
        "session" => GlobalId::<kind::Session>::new(oid).encode(),
        "key" => GlobalId::<kind::Key>::new(oid).encode(),
        "passkey" => GlobalId::<kind::Passkey>::new(oid).encode(),
        "client_credential" => GlobalId::<kind::ClientCredential>::new(oid).encode(),
        "audit_event" => GlobalId::<kind::AuditEvent>::new(oid).encode(),
        _ => return None,
    };
    Some(ID(encoded))
}
