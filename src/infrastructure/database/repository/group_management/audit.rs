//! Semantic group audit facts on the caller's transaction.

use identity_application::rbac::{GroupManagementRepositoryError, RbacManagementAuthority};
use identity_domain::audit::AuditRecord;
use sea_orm::DatabaseTransaction;

use crate::database::audit;

pub(crate) async fn append_semantic_audit(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    record: AuditRecord,
) -> Result<(), GroupManagementRepositoryError> {
    audit::record(txn, record.by(&authority.actor))
        .await
        .map_err(|error| GroupManagementRepositoryError::AuditFailed(Box::new(error)))
}
