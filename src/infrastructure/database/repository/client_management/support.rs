//! Error helpers for client management persistence.

use identity_application::{
    client::ClientManagementRepositoryError, rbac::RbacManagementRepositoryError,
};
use sea_orm::DbErr;

pub(super) fn storage(error: DbErr) -> ClientManagementRepositoryError {
    ClientManagementRepositoryError::Storage(Box::new(error))
}

pub(super) fn corrupt() -> ClientManagementRepositoryError {
    ClientManagementRepositoryError::CorruptRecord
}

/// The authority recheck and semantic audit are shared with RBAC management;
/// only their failure classes can occur here.
pub(super) fn from_management(
    error: RbacManagementRepositoryError,
) -> ClientManagementRepositoryError {
    use ClientManagementRepositoryError as Client;
    use RbacManagementRepositoryError as Shared;
    match error {
        Shared::Storage(source) => Client::Storage(source),
        Shared::Authorization(source) => Client::Authorization(source),
        Shared::AuditFailed(source) => Client::AuditFailed(source),
        Shared::LastRecoverableAdministrator => Client::LastRecoverableAdministrator,
        _ => Client::CorruptRecord,
    }
}
