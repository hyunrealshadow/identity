//! Security audit events, query domain models, native Lucene parser, and repository port.

pub mod event;
pub mod model;
pub mod query;
pub mod repository;

pub use event::{
    AuditAction, AuditActor, AuditActorKind, AuditAuthMethod, AuditCategory, AuditChange,
    AuditChangeValue, AuditChanges, AuditCorrelation, AuditFailureReason, AuditField, AuditOutcome,
    AuditRecord, AuditRef, AuditTargetKind,
};
pub use model::{
    AuditEvent, AuditEventOid, AuditEventOrder, AuditEventOrderDirection, AuditEventOrderField,
    AuditEventSortKey, AuditTarget,
};
pub use query::{
    AuditIdentifierMatch, AuditQueryError, AuditQueryExpr, AuditQueryField, AuditTextMatcher,
    AuditTimeBound, MAX_AUDIT_QUERY_CLAUSES, MAX_AUDIT_QUERY_DEPTH, MAX_AUDIT_QUERY_LENGTH,
    parse_audit_query,
};
pub use repository::{
    AuditEventPage, AuditEventPageDirection, AuditEventQuery, AuditEventRecord,
    AuditQueryRepository, AuditQueryRepositoryError,
};
