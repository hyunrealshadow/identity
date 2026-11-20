//! Security audit query domain models, native Lucene parser, and repository port.

pub mod model;
pub mod query;
pub mod repository;

pub use model::{
    AuditEvent, AuditEventOid, AuditEventOrder, AuditEventOrderDirection, AuditEventOrderField,
    AuditEventSortKey,
};
pub use query::{
    AuditIdentifierMatch, AuditQueryError, AuditQueryExpr, AuditQueryField, AuditTextMatcher,
    AuditTimeBound, MAX_AUDIT_QUERY_CLAUSES, MAX_AUDIT_QUERY_DEPTH, MAX_AUDIT_QUERY_LENGTH,
    parse_audit_query,
};
pub use repository::{
    AuditEventPage, AuditEventPageDirection, AuditEventQuery, AuditQueryRepository,
    AuditQueryRepositoryError,
};
