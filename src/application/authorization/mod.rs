//! Application authorization policies and transactional audit contract.
//!
//! This module is deliberately free of SeaORM, HTTP and GraphQL types. It is
//! the shared policy surface later GraphQL Guards and mutation services call.

pub mod audit;
pub mod error;
pub mod policy;

pub use audit::{
    AuditSubject, AuditSubjectKind, AuthorizationAuditContext, AuthorizationAuditError,
    AuthorizationAuditJournal, AuthorizationAuditStorageError,
};
pub use policy::{
    CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationDecision,
    ManagementAuthorizationError, ManagementAuthorizationRequest, ManagementTarget,
    ManagementTargetKind, evaluate_management_authority, parse_token_management_scopes,
};
