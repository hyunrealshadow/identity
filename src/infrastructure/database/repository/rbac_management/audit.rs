//! Semantic audit facts for RBAC mutations, on the caller's transaction.

use identity_application::rbac::{RbacManagementAuthority, RbacManagementRepositoryError};
use identity_domain::authorization::ActorPrincipal;
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, Statement, Value};
use uuid::Uuid;

use crate::database::repository::authorization_lifecycle;

pub(crate) async fn append_semantic_audit(
    txn: &DatabaseTransaction,
    authority: &RbacManagementAuthority,
    action: &'static str,
    target_type: &'static str,
    target_oid: Uuid,
    reason: &str,
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
    let (actor_type, actor_oid) = match &authority.actor.principal {
        ActorPrincipal::User { user_oid, .. } => ("user", Uuid::from(*user_oid)),
        ActorPrincipal::Client { client_oid } => ("client", *client_oid),
    };
    let trace_id = authority
        .actor
        .trace_id
        .as_ref()
        .map(|trace| trace.as_str().to_owned());
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
INSERT INTO security_audit (
    resource_type, resource_oid, subject_oid, operation, status,
    actor_type, actor_oid, action, target_type, target_oid,
    reason, request_id, trace_id, event_kind
) VALUES (
    $1, $2, CASE WHEN $3 = 'user' THEN $4::uuid ELSE NULL END, 'mutation', 'success',
    $3, $4, $5, $1, $2,
    $6, $7, $8, 'semantic'
)
"#,
        [
            target_type.to_owned().into(),
            target_oid.into(),
            actor_type.to_owned().into(),
            actor_oid.into(),
            action.to_owned().into(),
            reason.to_owned().into(),
            authority.actor.request_id.as_str().to_owned().into(),
            Value::String(trace_id),
        ],
    ))
    .await
    .map_err(|error| RbacManagementRepositoryError::AuditFailed(Box::new(error)))?;
    Ok(())
}
