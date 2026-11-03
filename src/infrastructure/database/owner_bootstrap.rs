//! Local operator bootstrap of an owner group membership.
//!
//! There is no HTTP or GraphQL entry point here. The first installation creates
//! its owner membership through [`crate::database::repository::install`]; this
//! module supports deliberate operator recovery through the same unified group
//! membership model used at installation.

use identity_application::{
    error::{AppError, codes::authorization::AuthorizationErrorCode as Code},
    setting::InstallationSettings,
};
use identity_domain::{
    authorization::{GrantReason, RequestId, catalog::AdministratorRole},
    rbac::{GroupMembershipOid, built_in_group_oid},
    user::UserOid,
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, Statement,
    TransactionTrait, Value,
};
use uuid::Uuid;

use crate::observability::context;

use super::{repository, repository::authorization_lifecycle};

#[tracing::instrument(
    skip_all,
    name = "db.query",
    fields(db.system = "postgresql", db.operation = "bootstrap_owner")
)]
pub async fn bootstrap_owner(
    db: &DatabaseConnection,
    user: UserOid,
    reason: GrantReason,
    request_id: RequestId,
) -> Result<Uuid, AppError> {
    let transaction = db.begin().await.map_err(AppError::internal)?;
    authorization_lifecycle::lock_owner_lifecycle(&transaction)
        .await
        .map_err(AppError::internal)?;
    let installed =
        repository::setting::read_section::<InstallationSettings, _>(&transaction).await?;
    if !installed.initialized {
        return Err(AppError::from_code(Code::InvalidTarget));
    }
    let target = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT version FROM \"user\" WHERE oid = $1",
            [user.0.into()],
        ))
        .await
        .map_err(AppError::internal)?;
    let Some(target) = target else {
        return Err(AppError::from_code(Code::InvalidTarget));
    };
    let target_version = target
        .try_get::<Uuid>("", "version")
        .map_err(AppError::internal)?;

    // Capability-based guard: a local bootstrap is only for recovering an
    // instance with no remaining usable full-capability user. Group membership
    // count, display names and role keys never decide this.
    let snapshot =
        authorization_lifecycle::recoverable_authorization_snapshot_in_txn(&transaction, user)
            .await
            .map_err(AppError::internal)?;
    if snapshot.target_is_active_owner || snapshot.other_active_owner_count > 0 {
        return Err(AppError::from_code(Code::VersionConflict)
            .with_param("current_version", target_version.to_string()));
    }

    let owner_group_id = built_in_group_id(&transaction, AdministratorRole::Owner).await?;

    let membership_oid = GroupMembershipOid::new();
    let record = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO group_membership(oid, group_id, user_id, granted_by_user_id, reason, \
                enabled, version, created_at) \
             SELECT $1, $2, u.id, NULL, $3, true, gen_random_uuid(), now() FROM \"user\" u \
             WHERE u.oid = $4 AND u.enabled AND NOT u.locked \
               AND EXISTS(SELECT 1 FROM user_credential uc WHERE uc.user_id = u.id \
                          AND uc.type IN ('password','passkey') \
                          AND (uc.expires_at IS NULL OR uc.expires_at > now())) \
             RETURNING user_id",
            [
                membership_oid.0.into(),
                owner_group_id.into(),
                reason.as_str().to_owned().into(),
                user.0.into(),
            ],
        ))
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::from_code(Code::InvalidTarget))?;
    let user_id = record
        .try_get::<i64>("", "user_id")
        .map_err(AppError::internal)?;
    authorization_lifecycle::renew_user_version_in_txn(&transaction, user_id)
        .await
        .map_err(AppError::internal)?;
    record_group_membership_audit(
        &transaction,
        "rbac.owner.bootstrap",
        membership_oid.0,
        reason.as_str(),
        &request_id,
    )
    .await?;
    transaction.commit().await.map_err(AppError::internal)?;
    Ok(membership_oid.0)
}

async fn built_in_group_id(
    transaction: &DatabaseTransaction,
    role: AdministratorRole,
) -> Result<i64, AppError> {
    let oid = built_in_group_oid(role).0;
    let row = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM user_group WHERE oid = $1 AND built_in = true AND enabled = true",
            [oid.into()],
        ))
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::map_source(Code::RbacPolicyUnavailable)(DbErr::Custom(
                "a trusted built-in group is missing; run the RBAC seed first".to_owned(),
            ))
        })?;
    row.try_get::<i64>("", "id").map_err(AppError::internal)
}

/// Append one system-actor semantic fact for a group membership transition.
pub(crate) async fn record_group_membership_audit(
    transaction: &DatabaseTransaction,
    action: &'static str,
    target_oid: Uuid,
    reason: &str,
    request_id: &RequestId,
) -> Result<(), AppError> {
    let trace_id =
        context::current_request_correlation().and_then(|correlation| correlation.trace_id);
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
INSERT INTO security_audit (
    resource_type, resource_oid, subject_oid, operation, status,
    actor_type, actor_oid, action, target_type, target_oid,
    reason, request_id, trace_id, event_kind
) VALUES (
    'group_membership', $1, NULL, 'mutation', 'success',
    'system', $2, $3, 'group_membership', $1,
    $4, $5, $6, 'semantic'
)
"#,
            [
                target_oid.into(),
                Uuid::nil().into(),
                action.into(),
                reason.to_owned().into(),
                request_id.as_str().to_owned().into(),
                Value::String(trace_id),
            ],
        ))
        .await
        .map_err(AppError::internal)?;
    Ok(())
}
