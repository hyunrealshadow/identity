use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::event::{
    AuditAction, AuditActor, AuditAuthMethod, AuditCategory, AuditChange, AuditFailureReason,
    AuditOutcome, AuditTargetKind,
};

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

/// An immutable audit record as persisted in `audit`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub oid: AuditEventOid,
    pub occurred_at: DateTime<Utc>,
    pub category: AuditCategory,
    pub action: AuditAction,
    pub outcome: AuditOutcome,
    pub failure_reason: Option<AuditFailureReason>,
    pub actor: AuditActor,
    pub target: Option<AuditTarget>,
    pub client_oid: Option<Uuid>,
    pub auth_methods: Vec<AuditAuthMethod>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub changes: Vec<AuditChange>,
}

/// The object an audited action applied to, with its display snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTarget {
    pub kind: AuditTargetKind,
    pub oid: Uuid,
    pub label: Option<String>,
}

/// Stable keyset tie-breaker for security audit event pagination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEventSortKey {
    pub occurred_at: DateTime<Utc>,
    pub id: i64,
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
