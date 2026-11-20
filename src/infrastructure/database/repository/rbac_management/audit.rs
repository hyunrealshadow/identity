//! Semantic audit facts for RBAC mutations, on the caller's transaction.

use identity_application::rbac::{RbacManagementAuthority, RbacManagementRepositoryError};
use std::collections::BTreeSet;

use identity_domain::audit::{AuditRecord, AuditRef, AuditTargetKind};
use sea_orm::{
    ColumnTrait, DatabaseTransaction, DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
};
use uuid::Uuid;

use crate::database::{
    audit,
    entity::{role, scope, user},
    repository::authorization_lifecycle,
};

/// Rejects the change if it removed the last recoverable authorization
/// administrator, then records it as performed by `authority`.
pub(crate) async fn append_semantic_audit(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    record: AuditRecord,
) -> Result<(), RbacManagementRepositoryError> {
    authorization_lifecycle::ensure_recoverable_authorization_administrator(txn)
        .await
        .map_err(|error| match &error {
            DbErr::Custom(message)
                if message == "no recoverable authorization administrator remains" =>
            {
                RbacManagementRepositoryError::LastRecoverableAdministrator
            }
            _ => RbacManagementRepositoryError::Storage(Box::new(error)),
        })?;
    audit::record(txn, record.by(&authority.actor))
        .await
        .map_err(|error| RbacManagementRepositoryError::AuditFailed(Box::new(error)))
}

/// Audit references for scopes identified by row id, in code order.
pub(crate) async fn scope_refs(
    txn: &DatabaseTransaction,
    ids: &BTreeSet<i64>,
) -> Result<Vec<AuditRef>, RbacManagementRepositoryError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = scope::Entity::find()
        .select_only()
        .columns([scope::Column::Oid, scope::Column::Code])
        .filter(scope::Column::Id.is_in(ids.iter().copied()))
        .order_by_asc(scope::Column::Code)
        .into_tuple::<(Uuid, String)>()
        .all(txn)
        .await
        .map_err(|error| RbacManagementRepositoryError::Storage(Box::new(error)))?;
    Ok(rows
        .into_iter()
        .map(|(oid, code)| AuditRef::new(AuditTargetKind::Scope, oid, code))
        .collect())
}

/// Audit references for roles identified by row id, in name order.
pub(crate) async fn role_refs(
    txn: &DatabaseTransaction,
    ids: &[i64],
) -> Result<Vec<AuditRef>, DbErr> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = role::Entity::find()
        .select_only()
        .columns([role::Column::Oid, role::Column::Name])
        .filter(role::Column::Id.is_in(ids.iter().copied()))
        .order_by_asc(role::Column::Name)
        .into_tuple::<(Uuid, String)>()
        .all(txn)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(oid, name)| AuditRef::new(AuditTargetKind::Role, oid, name))
        .collect())
}

/// Audit reference for a user, with its current name.
pub(crate) async fn user_ref(txn: &DatabaseTransaction, oid: Uuid) -> Result<AuditRef, DbErr> {
    let name = user::Entity::find()
        .select_only()
        .column(user::Column::Name)
        .filter(user::Column::Oid.eq(oid))
        .into_tuple::<String>()
        .one(txn)
        .await?;
    Ok(AuditRef::new(AuditTargetKind::User, oid, name))
}
