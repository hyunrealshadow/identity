//! Instance administrator management.
//!
//! Administrator bindings are a separate authorization relation from business
//! roles and from machine client management grants. The public surface is
//! re-exported here so GraphQL adapters use
//! `identity_application::administrator::{...}` without depending on the
//! internal file layout.

mod cursor;
pub mod model;
pub mod repository;
pub mod service;

pub use model::{
    AdministratorFilter, AdministratorManagementAuthority, AdministratorOrder, AdministratorPage,
    AdministratorPageItem, AdministratorPageRequest, AssignAdministratorCommand, DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE, MAX_QUERY_FILTER_LENGTH, MAX_REASON_LENGTH, RevokeAdministratorCommand,
    UpdateAdministratorRoleCommand,
};
pub use repository::{
    AdministratorManagementRepository, AdministratorManagementRepositoryError,
    AdministratorPageData, AdministratorPageDirection, AdministratorPageEntry, AdministratorQuery,
    AdministratorSortKey, AssignAdministratorTransaction, RevokeAdministratorTransaction,
    SharedAdministratorManagementRepository, UpdateAdministratorRoleTransaction,
};
pub use service::AdministratorManagementService;
