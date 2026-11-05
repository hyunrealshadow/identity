//! OAuth client management: client definitions, protocol settings,
//! credentials and lifecycle. Scope assignment lives with the scope catalog in
//! `rbac`.

pub mod model;
pub mod repository;
pub mod service;

pub use model::*;
pub use repository::{
    ClientEntityKind, ClientManagementRepository, ClientManagementRepositoryError, ClientPageData,
    ClientPageEntry, ClientQuery, ClientStateTransaction, CreateClientSecretTransaction,
    CreateClientTransaction, NewClientSecret, RevokeClientCredentialTransaction,
    SharedClientManagementRepository, UpdateClientTransaction,
};
pub use service::ClientManagementService;
