//! Application-facing transactional audit port.
//!
//! The concrete PostgreSQL adapter lives in infrastructure and inserts into
//! `security_audit` on the business mutation's transaction. This module only
//! re-exports the domain-safe contract so application use cases do not import
//! SeaORM types.

pub use identity_domain::authorization::audit::{
    AuditSubject, AuditSubjectKind, AuthorizationAuditContext, AuthorizationAuditError,
    AuthorizationAuditJournal, AuthorizationAuditStorageError,
};
