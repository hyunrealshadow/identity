use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable UUID object identifier (`oid`) of a persisted security audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditEventOid(pub Uuid);

impl AuditEventOid {
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AuditEventOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Uuid> for AuditEventOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<AuditEventOid> for Uuid {
    fn from(value: AuditEventOid) -> Self {
        value.0
    }
}

/// Immutable semantic security audit record persisted in `security_audit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: i64,
    pub oid: AuditEventOid,
    pub occurred_at: DateTime<Utc>,
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

/// Stable keyset tie-breaker for security audit event pagination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEventSortKey {
    pub occurred_at: DateTime<Utc>,
    pub id: i64,
}

impl AuditEventSortKey {
    #[must_use]
    pub const fn from_event(event: &AuditEvent) -> Self {
        Self {
            occurred_at: event.occurred_at,
            id: event.id,
        }
    }
}

/// Supported sort fields for security audit event connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuditEventOrderField {
    #[default]
    OccurredAt,
}

/// Sort directions for security audit event connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuditEventOrderDirection {
    Asc,
    #[default]
    Desc,
}

/// Order specification for querying security audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuditEventOrder {
    pub field: AuditEventOrderField,
    pub direction: AuditEventOrderDirection,
}
