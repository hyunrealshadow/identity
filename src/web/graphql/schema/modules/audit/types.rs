use async_graphql::{Context, Enum, ID, Json, Object, Result as GraphqlResult, SimpleObject};
use chrono::{DateTime, Utc};
use identity_application::{authorization::ManagementTarget, client::ClientRecord};
use identity_domain::{
    audit::{
        self as domain, AuditChangeValue, AuditEvent, AuditEventOid,
        AuditEventOrder as DomainAuditEventOrder, AuditEventOrderDirection, AuditEventOrderField,
    },
    authorization::ManagementScope,
    global_id::{GlobalId, kind},
    user::{User, UserOid},
};
use serde_json::Value;
use uuid::Uuid;

use super::{
    super::{
        account::UserNode,
        client::{self, types::ClientNode},
        resource::support::decode_oid,
        user,
    },
    enums::{
        AuditAction, AuditActorKind, AuditAuthMethod, AuditCategory, AuditFailureReason,
        AuditField, AuditOutcome, AuditTargetKind,
    },
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

/// The Global ID of an audited object, when its kind has one.
fn global_id(kind: domain::AuditTargetKind, oid: Uuid) -> Option<ID> {
    use domain::AuditTargetKind as Kind;
    let encoded = match kind {
        Kind::User => GlobalId::<kind::User>::new(oid).encode(),
        Kind::Client => GlobalId::<kind::Client>::new(oid).encode(),
        Kind::Role => GlobalId::<kind::Role>::new(oid).encode(),
        Kind::Group => GlobalId::<kind::Group>::new(oid).encode(),
        Kind::Scope => GlobalId::<kind::Scope>::new(oid).encode(),
        Kind::Resource => GlobalId::<kind::Resource>::new(oid).encode(),
        Kind::Key => GlobalId::<kind::Key>::new(oid).encode(),
        Kind::Session => GlobalId::<kind::Session>::new(oid).encode(),
        Kind::Passkey => GlobalId::<kind::Passkey>::new(oid).encode(),
        Kind::Setting | Kind::Authorization | Kind::DeviceAuthorization => return None,
    };
    Some(ID(encoded))
}

/// Users and clients already loaded for a page of events.
#[derive(Default, Clone)]
pub(crate) struct PreloadedActor {
    pub(crate) user: Option<User>,
    pub(crate) user_loaded: bool,
    pub(crate) client: Option<ClientRecord>,
    pub(crate) client_loaded: bool,
}

pub(crate) struct AuditEventNode {
    id: ID,
    event: AuditEvent,
    preloaded: PreloadedActor,
}

impl AuditEventNode {
    pub(crate) fn new(event: AuditEvent) -> Self {
        Self::with_preloaded_actor(event, PreloadedActor::default())
    }

    pub(crate) fn with_preloaded_actor(event: AuditEvent, preloaded: PreloadedActor) -> Self {
        Self {
            id: audit_event_global_id(event.oid),
            event,
            preloaded,
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
    async fn category(&self) -> AuditCategory {
        self.event.category.into()
    }

    #[graphql(complexity = 0)]
    async fn action(&self) -> AuditAction {
        self.event.action.into()
    }

    #[graphql(complexity = 0)]
    async fn outcome(&self) -> AuditOutcome {
        self.event.outcome.into()
    }

    #[graphql(complexity = 0)]
    async fn failure_reason(&self) -> Option<AuditFailureReason> {
        self.event.failure_reason.map(Into::into)
    }

    #[graphql(complexity = 0)]
    async fn actor(&self) -> AuditActorNode<'_> {
        AuditActorNode {
            actor: &self.event.actor,
            preloaded: &self.preloaded,
        }
    }

    #[graphql(complexity = 0)]
    async fn target(&self) -> Option<AuditTargetNode> {
        self.event.target.as_ref().map(|target| AuditTargetNode {
            kind: target.kind.into(),
            id: global_id(target.kind, target.oid),
            oid: target.oid.to_string(),
            label: target.label.clone(),
        })
    }

    /// The OAuth client application through which the action happened.
    #[graphql(complexity = 0)]
    async fn client_id(&self) -> Option<ID> {
        self.event
            .client_oid
            .and_then(|oid| global_id(domain::AuditTargetKind::Client, oid))
    }

    #[graphql(complexity = 0)]
    async fn auth_methods(&self) -> Vec<AuditAuthMethod> {
        self.event
            .auth_methods
            .iter()
            .copied()
            .map(Into::into)
            .collect()
    }

    #[graphql(complexity = 0)]
    async fn ip_address(&self) -> Option<&str> {
        self.event.ip_address.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn user_agent(&self) -> Option<&str> {
        self.event.user_agent.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn request_id(&self) -> Option<&str> {
        self.event.request_id.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn trace_id(&self) -> Option<&str> {
        self.event.trace_id.as_deref()
    }

    #[graphql(complexity = 0)]
    async fn changes(&self) -> Vec<AuditChangeNode> {
        self.event
            .changes
            .iter()
            .map(AuditChangeNode::from)
            .collect()
    }
}

/// Who performed an audited action.
pub(crate) struct AuditActorNode<'a> {
    actor: &'a domain::AuditActor,
    preloaded: &'a PreloadedActor,
}

#[Object(name = "AuditActor")]
impl AuditActorNode<'_> {
    #[graphql(complexity = 0)]
    async fn kind(&self) -> AuditActorKind {
        self.actor.kind.into()
    }

    /// Global ID of the user or client actor.
    #[graphql(complexity = 0)]
    async fn id(&self) -> Option<ID> {
        let oid = self.actor.oid?;
        match self.actor.kind {
            domain::AuditActorKind::User => global_id(domain::AuditTargetKind::User, oid),
            domain::AuditActorKind::Client => global_id(domain::AuditTargetKind::Client, oid),
            domain::AuditActorKind::System | domain::AuditActorKind::Anonymous => None,
        }
    }

    #[graphql(complexity = 0)]
    async fn oid(&self) -> Option<String> {
        self.actor.oid.map(|oid| oid.to_string())
    }

    /// Display name when the action happened.
    #[graphql(complexity = 0)]
    async fn label(&self) -> Option<&str> {
        self.actor.label.as_deref()
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead))
    )]
    async fn user(&self, ctx: &Context<'_>) -> GraphqlResult<Option<UserNode>> {
        let Some(oid) = self
            .actor
            .oid
            .filter(|_| self.actor.kind == domain::AuditActorKind::User)
        else {
            return Ok(None);
        };
        if self.preloaded.user_loaded {
            return Ok(self.preloaded.user.clone().map(UserNode::managed));
        }
        let request = request_context(ctx)?;
        let user = user::integration::find_user(request, UserOid(oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(user.map(UserNode::managed))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead))
    )]
    async fn client(&self, ctx: &Context<'_>) -> GraphqlResult<Option<ClientNode>> {
        let Some(oid) = self
            .actor
            .oid
            .filter(|_| self.actor.kind == domain::AuditActorKind::Client)
        else {
            return Ok(None);
        };
        if self.preloaded.client_loaded {
            return Ok(self.preloaded.client.clone().map(ClientNode::new));
        }
        let request = request_context(ctx)?;
        let client = client::integration::find_client(request, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(client.map(ClientNode::new))
    }
}

/// The object an audited action applied to.
#[derive(SimpleObject)]
#[graphql(name = "AuditTarget")]
pub(crate) struct AuditTargetNode {
    kind: AuditTargetKind,
    /// Global ID, for kinds that have one.
    id: Option<ID>,
    oid: String,
    /// Display name when the action happened.
    label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditChangeKind")]
pub(crate) enum AuditChangeKind {
    /// `oldValue` and `newValue` hold the values.
    Value,
    /// `added` and `removed` hold collection members.
    Set,
    /// A secret changed; its values are never recorded.
    Redacted,
}

/// One changed attribute of an audited object.
#[derive(SimpleObject)]
#[graphql(name = "AuditChange")]
pub(crate) struct AuditChangeNode {
    field: AuditField,
    kind: AuditChangeKind,
    old_value: Option<Json<Value>>,
    new_value: Option<Json<Value>>,
    added: Vec<Json<Value>>,
    removed: Vec<Json<Value>>,
}

impl From<&domain::AuditChange> for AuditChangeNode {
    fn from(change: &domain::AuditChange) -> Self {
        let field = change.field.into();
        match &change.value {
            AuditChangeValue::Value { old, new } => Self {
                field,
                kind: AuditChangeKind::Value,
                old_value: old.clone().map(Json),
                new_value: new.clone().map(Json),
                added: Vec::new(),
                removed: Vec::new(),
            },
            AuditChangeValue::Set { added, removed } => Self {
                field,
                kind: AuditChangeKind::Set,
                old_value: None,
                new_value: None,
                added: added.iter().cloned().map(Json).collect(),
                removed: removed.iter().cloned().map(Json).collect(),
            },
            AuditChangeValue::Redacted => Self {
                field,
                kind: AuditChangeKind::Redacted,
                old_value: None,
                new_value: None,
                added: Vec::new(),
                removed: Vec::new(),
            },
        }
    }
}
