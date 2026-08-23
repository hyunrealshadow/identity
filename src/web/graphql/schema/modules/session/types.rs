use async_graphql::{ID, Object};
use identity_domain::auth::{SessionOid, model::Session};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};
use uuid::Uuid;

pub(crate) struct SessionGlobalId;

impl GlobalIdType for SessionGlobalId {
    const TYPE_NAME: &'static str = "Session";
}

pub(crate) struct SessionNode {
    id: ID,
    session: Session,
    current: bool,
}

impl SessionNode {
    pub(crate) fn new(session: Session, current_session_oid: SessionOid) -> Self {
        Self {
            id: GlobalId::<SessionGlobalId>::new(Uuid::from(session.oid)).into(),
            current: session.oid == current_session_oid,
            session,
        }
    }
}

#[Object(name = "Session")]
impl SessionNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    async fn status(&self) -> &str {
        &self.session.status
    }

    async fn current(&self) -> bool {
        self.current
    }

    async fn device_name(&self) -> Option<&str> {
        self.session.device_name.as_deref()
    }

    async fn device_type(&self) -> Option<&str> {
        self.session.device_type.as_deref()
    }

    async fn os_name(&self) -> Option<&str> {
        self.session.os_name.as_deref()
    }

    async fn os_version(&self) -> Option<&str> {
        self.session.os_version.as_deref()
    }

    async fn browser_name(&self) -> Option<&str> {
        self.session.browser_name.as_deref()
    }

    async fn browser_version(&self) -> Option<&str> {
        self.session.browser_version.as_deref()
    }

    async fn ip_address(&self) -> Option<&str> {
        self.session.ip_address.as_deref()
    }

    async fn last_active_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.session.last_active_at
    }

    async fn expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.session.expires_at
    }

    async fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.session.created_at
    }
}

pub(super) struct RevokeSessionPayload {
    session: SessionNode,
    client_mutation_id: Option<String>,
}

impl RevokeSessionPayload {
    pub(super) fn new(session: SessionNode, client_mutation_id: Option<String>) -> Self {
        Self {
            session,
            client_mutation_id,
        }
    }
}

#[Object]
impl RevokeSessionPayload {
    async fn session(&self) -> &SessionNode {
        &self.session
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(super) struct RevokeOtherSessionsPayload {
    revoked_count: i32,
    client_mutation_id: Option<String>,
}

impl RevokeOtherSessionsPayload {
    pub(super) fn new(revoked_count: i32, client_mutation_id: Option<String>) -> Self {
        Self {
            revoked_count,
            client_mutation_id,
        }
    }
}

#[Object]
impl RevokeOtherSessionsPayload {
    async fn revoked_count(&self) -> i32 {
        self.revoked_count
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}
