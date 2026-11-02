//! Transactional authorization audit contract.
//!
//! PostgreSQL `security_audit` is the authoritative security fact journal.
//! `EventSink`/tracing is a diagnostic copy and must never be treated as audit
//! storage. Implementations of [`AuthorizationAuditJournal`] and the
//! transaction-scoped helper must insert a semantic row on the caller's
//! transaction; any failure propagates and rolls back the business mutation.

use std::error::Error as StdError;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::actor::{RequestId, TraceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditSubjectKind {
    User,
    Client,
    Resource,
    Role,
    Permission,
    Binding,
    ClientGrant,
    Setting,
    Session,
    System,
}

impl AuditSubjectKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Client => "client",
            Self::Resource => "resource",
            Self::Role => "role",
            Self::Permission => "permission",
            Self::Binding => "administrator_binding",
            Self::ClientGrant => "client_management_grant",
            Self::Setting => "setting",
            Self::Session => "session",
            Self::System => "system",
        }
    }
}

/// Actor or target identity for a semantic audit row. The OID is always the
/// stable database OID, never a display name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSubject {
    pub kind: AuditSubjectKind,
    pub oid: Uuid,
}

impl AuditSubject {
    #[must_use]
    pub const fn new(kind: AuditSubjectKind, oid: Uuid) -> Self {
        Self { kind, oid }
    }
}

/// Context for one semantic authorization fact. `action` must be a stable
/// machine name (for example `administrator.binding.revoke`); it is not a
/// translated label. `reason` is operator-supplied text and must not contain
/// credentials or secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationAuditContext {
    pub actor: AuditSubject,
    pub action: &'static str,
    pub target: AuditSubject,
    pub reason: String,
    pub request_id: RequestId,
    pub trace_id: Option<TraceId>,
    pub recorded_at: Option<DateTime<Utc>>,
}

impl AuthorizationAuditContext {
    #[must_use]
    pub fn new(
        actor: AuditSubject,
        action: &'static str,
        target: AuditSubject,
        reason: impl Into<String>,
        request_id: RequestId,
        trace_id: Option<TraceId>,
    ) -> Self {
        Self {
            actor,
            action,
            target,
            reason: reason.into(),
            request_id,
            trace_id,
            recorded_at: None,
        }
    }

    #[must_use]
    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.recorded_at.unwrap_or_else(Utc::now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationAuditError {
    #[error("failed to append the transactional security audit fact")]
    WriteFailed,
    #[error("audit context has an invalid target or action")]
    InvalidContext,
}

/// Port for audit append. Implementations used by business mutations must
/// execute on the mutation's own transaction. A standalone implementation is
/// only suitable for rejected/failed events that have no business write.
#[async_trait::async_trait]
pub trait AuthorizationAuditJournal: Send + Sync {
    async fn record(
        &self,
        context: &AuthorizationAuditContext,
    ) -> Result<(), AuthorizationAuditError>;
}

#[derive(Debug, thiserror::Error)]
#[error("authorization audit journal failure")]
pub struct AuthorizationAuditStorageError(#[source] pub Box<dyn StdError + Send + Sync + 'static>);

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{AuditSubject, AuditSubjectKind, AuthorizationAuditContext};
    use crate::authorization::actor::RequestId;

    #[test]
    fn audit_context_keeps_request_and_trace_identifiers_distinct() {
        let context = AuthorizationAuditContext::new(
            AuditSubject::new(AuditSubjectKind::User, Uuid::new_v4()),
            "administrator.binding.revoke",
            AuditSubject::new(AuditSubjectKind::Binding, Uuid::new_v4()),
            "owner cleanup",
            RequestId::new("request-1").unwrap(),
            None,
        );
        assert_eq!(context.request_id.as_str(), "request-1");
        assert!(context.trace_id.is_none());
    }
}
