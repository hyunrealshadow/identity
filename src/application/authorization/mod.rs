//! Application authorization policies.
//!
//! This module is deliberately free of SeaORM, HTTP and GraphQL types. It is
//! the shared policy surface later GraphQL Guards and mutation services call.

pub mod access;
pub mod error;
pub mod policy;
pub mod validation;

pub use access::{
    EffectiveManagementPermissions, ManagementAccessRequest, ManagementAccessService,
    ManagementPrincipal,
};

pub use policy::{
    CurrentManagementAuthority, DEFAULT_RECENT_AAL2_TTL, ManagementAuthorizationDecision,
    ManagementAuthorizationError, ManagementAuthorizationRequest, ManagementTarget,
    ManagementTargetKind, evaluate_management_authority, parse_token_management_scopes,
};

pub use validation::{
    MAX_CLIENT_MUTATION_ID_LENGTH, MAX_REASON_LENGTH, validate_client_mutation_id_with,
    validate_reason_with,
};
