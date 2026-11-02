//! P2 instance user management.
//!
//! The public surface is re-exported here so adapters can use
//! `identity_application::user::management::{...}` without depending on the
//! internal file layout.

mod cursor;
pub mod model;
pub mod repository;
pub mod service;

pub use model::{
    CreateUserCommand, UpdateUserCommand, UserFilter, UserManagementAuthority,
    UserManagementMutationResult, UserManagementPage, UserManagementPageItem, UserOrder,
    UserPageRequest, UserPassword, UserProfilePatch, UserRecord, UserStateCommand,
};
pub use repository::{
    CreateUserTransaction, UpdateUserTransaction, UserIdentifierValue,
    UserManagementMutationOutcome, UserManagementPageData, UserManagementPageEntry,
    UserManagementQuery, UserManagementRepository, UserManagementRepositoryError,
    UserPageDirection, UserSortKey, UserStateTransaction,
};
pub use service::{
    DEFAULT_PAGE_SIZE, MAX_CLIENT_MUTATION_ID_LENGTH, MAX_EMAIL_FILTER_LENGTH, MAX_PAGE_SIZE,
    MAX_QUERY_FILTER_LENGTH, MAX_REASON_LENGTH, MAX_USERNAME_FILTER_LENGTH, UserManagementService,
};
