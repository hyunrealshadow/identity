//! SeaORM implementation of human management authorization persistence.
//!
//! Management authority is read from the unified user/group/role/scope graph.
//! A management scope is a canonical `scope` row owned by the GraphQL resource;
//! `role_permission` references `scope.id` directly. There is no separate
//! permission catalog, no client-management grant and no client-management
//! policy switch.

pub(crate) use super::client_authority::load_client_scope_authority;

use std::collections::BTreeSet;

use async_trait::async_trait;
use identity_domain::{
    authorization::{
        ManagementGrantKind,
        audit::{
            AuditSubjectKind, AuthorizationAuditContext, AuthorizationAuditError,
            AuthorizationAuditJournal, AuthorizationAuditStorageError,
        },
        authority::{
            ClientScopeAuthority, UserPermissionAuthority, is_trusted_management_permission,
        },
        catalog::ManagementScope,
        ids::PolicyVersion,
        policy_fingerprint,
        recovery::{OwnerAccessSnapshot, OwnerRecoverabilityError, OwnerRecoverabilityPort},
        repository::{ManagementAuthorityRepository, ManagementRepositoryError},
        snapshot,
        snapshot::ManagementAuthorizationSnapshot,
    },
    client::model::ClientOid,
    user::UserOid,
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, Statement,
    TransactionTrait, Value,
};
use serde_json::Value as SerdeJsonValue;
use uuid::Uuid;

use super::authorization_lifecycle::recoverable_authorization_snapshot_in_txn;
use crate::database::authority_snapshot::user_authority_fingerprint;

pub struct AuthorizationRepositoryImpl {
    db: DatabaseConnection,
}

impl AuthorizationRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage(error: DbErr) -> ManagementRepositoryError {
    ManagementRepositoryError::Storage(Box::new(error))
}

/// Load the whole-user effective management authority.
///
/// Reads only:
/// - an enabled user and its semantic authorization dependencies;
/// - active direct `user_role` rows;
/// - active `group_membership` -> enabled `user_group` ->
///   active `group_role` rows;
/// - enabled role, `role_permission`, canonical `scope`, and the exact
///   `urn:identity:graphql` resource.
///
/// Management scope rows must be enabled, `built_in = true`, carry the exact
/// trusted catalog code and match the trusted deterministic scope OID. A
/// database boolean, display name or role key alone never creates authority.
/// Business permissions and unknown scopes are ignored rather than promoted.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "load_user_permission_authority"))]
pub(crate) async fn load_user_permission_authority(
    txn: &DatabaseTransaction,
    user_oid: UserOid,
) -> Result<Option<UserPermissionAuthority>, DbErr> {
    // The permission set and the derived authority fingerprint must come from
    // one transaction snapshot. Callers open repeatable read when they only
    // read; mutating callers already own a transaction.
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
WITH effective AS (
    SELECT urb.user_id AS user_id,
           scope.oid AS permission_oid,
           scope.code AS permission_code,
           scope.code AS scope_code,
           resource.uri AS resource_uri,
           scope.enabled AS permission_enabled,
           scope.built_in AS permission_built_in
    FROM user_role urb
    JOIN "role" rl ON rl.id = urb.role_id
    JOIN role_permission rpr ON rpr.role_id = rl.id
    JOIN scope ON scope.id = rpr.scope_id
    JOIN resource ON resource.oid = scope.resource_id AND resource.enabled = true
    WHERE urb.enabled = true AND urb.revoked_at IS NULL
      AND rl.enabled = true
    UNION
    SELECT gm.user_id,
           scope.oid,
           scope.code,
           scope.code,
           resource.uri,
           scope.enabled,
           scope.built_in
    FROM group_membership gm
    JOIN user_group ug ON ug.id = gm.group_id
    JOIN group_role grb ON grb.group_id = ug.id
    JOIN "role" rl ON rl.id = grb.role_id
    JOIN role_permission rpr ON rpr.role_id = rl.id
    JOIN scope ON scope.id = rpr.scope_id
    JOIN resource ON resource.oid = scope.resource_id AND resource.enabled = true
    WHERE gm.enabled = true AND gm.revoked_at IS NULL
      AND ug.enabled = true AND ug.deleted_at IS NULL
      AND grb.enabled = true AND grb.revoked_at IS NULL
      AND rl.enabled = true
)
SELECT COALESCE(
           jsonb_agg(jsonb_build_object(
               'permission_oid', e.permission_oid,
               'permission_code', e.permission_code,
               'scope_code', e.scope_code,
               'permission_enabled', e.permission_enabled,
               'permission_built_in', e.permission_built_in
           )) FILTER (
               WHERE e.permission_oid IS NOT NULL
                 AND e.resource_uri = 'urn:identity:graphql'
           ),
           '[]'::jsonb
       ) AS permissions
FROM "user" u
LEFT JOIN effective e ON e.user_id = u.id
WHERE u.oid = $1 AND u.enabled = true
GROUP BY u.id
"#,
            [user_oid.0.into()],
        ))
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let permission_rows = row
        .try_get::<serde_json::Value>("", "permissions")?
        .as_array()
        .cloned()
        .ok_or_else(|| DbErr::Custom("permission authority payload is invalid".to_owned()))?;

    let mut permissions = BTreeSet::new();
    for permission in permission_rows {
        if !permission
            .get("permission_enabled")
            .and_then(SerdeJsonValue::as_bool)
            .unwrap_or(false)
            || !permission
                .get("permission_built_in")
                .and_then(SerdeJsonValue::as_bool)
                .unwrap_or(false)
        {
            continue;
        }
        let Some(scope_code) = permission
            .get("scope_code")
            .and_then(SerdeJsonValue::as_str)
        else {
            continue;
        };
        let Some(scope) = ManagementScope::from_name(scope_code) else {
            continue;
        };
        let Some(permission_oid) = permission
            .get("permission_oid")
            .and_then(SerdeJsonValue::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            continue;
        };
        let Some(permission_code) = permission
            .get("permission_code")
            .and_then(SerdeJsonValue::as_str)
        else {
            continue;
        };
        if !is_trusted_management_permission(scope, permission_oid, permission_code) {
            continue;
        }
        permissions.insert(scope);
    }

    // The authority identity is the derived semantic fingerprint, never the
    // user record's optimistic-lock version.
    let version = user_authority_fingerprint(txn, user_oid).await?;

    Ok(Some(UserPermissionAuthority {
        user_oid,
        version,
        permissions,
    }))
}

fn audit_actor_type(audit: &AuthorizationAuditContext) -> &'static str {
    match audit.actor.kind {
        AuditSubjectKind::User => "user",
        AuditSubjectKind::Client => "client",
        AuditSubjectKind::System => "system",
        _ => audit.actor.kind.as_str(),
    }
}

/// Append one semantic audit fact on the caller's transaction. Any error must
/// be propagated so the business write rolls back.
pub async fn append_semantic_audit(
    txn: &DatabaseTransaction,
    context: &AuthorizationAuditContext,
) -> Result<(), AuthorizationAuditStorageError> {
    let trace_id = context
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
    $1, $2, CASE WHEN $3 = 'user' THEN $4::uuid ELSE NULL END, 'authorization', 'success',
    $3, $4, $5, $6, $7,
    $8, $9, $10, 'semantic'
)
"#,
        [
            context.target.kind.as_str().to_owned().into(),
            context.target.oid.into(),
            audit_actor_type(context).to_owned().into(),
            context.actor.oid.into(),
            context.action.to_owned().into(),
            context.target.kind.as_str().to_owned().into(),
            context.target.oid.into(),
            context.reason.clone().into(),
            context.request_id.as_str().to_owned().into(),
            Value::String(trace_id),
        ],
    ))
    .await
    .map_err(|error| AuthorizationAuditStorageError(Box::new(error)))?;
    Ok(())
}

#[async_trait]
impl ManagementAuthorityRepository for AuthorizationRepositoryImpl {
    async fn find_user_permission_authority(
        &self,
        user_oid: UserOid,
    ) -> Result<Option<UserPermissionAuthority>, ManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        txn.execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
        ))
        .await
        .map_err(storage)?;
        let authority = load_user_permission_authority(&txn, user_oid).await;
        match authority {
            Ok(authority) => {
                txn.commit().await.map_err(storage)?;
                Ok(authority)
            }
            Err(error) => {
                let _ = txn.rollback().await;
                Err(storage(error))
            }
        }
    }

    async fn current_policy_version(&self) -> Result<PolicyVersion, ManagementRepositoryError> {
        Ok(policy_fingerprint())
    }

    async fn find_client_scope_authority(
        &self,
        client_oid: ClientOid,
    ) -> Result<Option<ClientScopeAuthority>, ManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        let result = load_client_scope_authority(&txn, client_oid)
            .await
            .map_err(storage);
        match result {
            Ok(authority) => {
                txn.commit().await.map_err(storage)?;
                Ok(authority)
            }
            Err(error) => {
                let _ = txn.rollback().await;
                Err(error)
            }
        }
    }

    async fn validate_snapshot(
        &self,
        snapshot: &ManagementAuthorizationSnapshot,
    ) -> Result<(), ManagementRepositoryError> {
        match snapshot.grant_kind {
            ManagementGrantKind::UserRbac => {
                // Effective permissions, the derived authority fingerprint and
                // the policy version must all come from one repeatable-read
                // view; otherwise an old permission set could be paired with a
                // freshly rotated fingerprint.
                let txn = self.db.begin().await.map_err(storage)?;
                txn.execute_raw(Statement::from_string(
                    DbBackend::Postgres,
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
                ))
                .await
                .map_err(storage)?;
                let current =
                    load_user_permission_authority(&txn, UserOid(snapshot.grant_oid)).await;
                let result = match current {
                    Ok(current) => snapshot::validate_user_permission_snapshot(
                        snapshot,
                        current.as_ref(),
                        policy_fingerprint(),
                    )
                    .map_err(|_| ManagementRepositoryError::StaleSnapshot),
                    Err(error) => Err(storage(error)),
                };
                match result {
                    Ok(()) => {
                        txn.commit().await.map_err(storage)?;
                        Ok(())
                    }
                    Err(error) => {
                        let _ = txn.rollback().await;
                        Err(error)
                    }
                }
            }
            // Retired binding snapshots never validate through the current
            // human authority port.
            ManagementGrantKind::AdministratorBinding => {
                Err(ManagementRepositoryError::StaleSnapshot)
            }
        }
    }
}

#[async_trait]
impl OwnerRecoverabilityPort for AuthorizationRepositoryImpl {
    async fn owner_access_snapshot(
        &self,
        target: UserOid,
    ) -> Result<OwnerAccessSnapshot, OwnerRecoverabilityError> {
        let fail = |error: DbErr| OwnerRecoverabilityError::Storage(Box::new(error));
        let txn = self.db.begin().await.map_err(fail)?;
        let snapshot = recoverable_authorization_snapshot_in_txn(&txn, target)
            .await
            .map_err(fail)?;
        txn.commit().await.map_err(fail)?;
        Ok(snapshot)
    }
}

#[async_trait]
impl AuthorizationAuditJournal for AuthorizationRepositoryImpl {
    async fn record(
        &self,
        context: &AuthorizationAuditContext,
    ) -> Result<(), AuthorizationAuditError> {
        let txn = self
            .db
            .begin()
            .await
            .map_err(|_| AuthorizationAuditError::WriteFailed)?;
        append_semantic_audit(&txn, context)
            .await
            .map_err(|_| AuthorizationAuditError::WriteFailed)?;
        txn.commit()
            .await
            .map_err(|_| AuthorizationAuditError::WriteFailed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use identity_domain::authorization::{
        RequestId,
        audit::{AuditSubject, AuditSubjectKind, AuthorizationAuditContext},
    };
    use uuid::Uuid;

    use super::audit_actor_type;

    #[test]
    fn audit_actor_type_never_confuses_human_and_machine() {
        let user = AuthorizationAuditContext::new(
            AuditSubject::new(AuditSubjectKind::User, Uuid::new_v4()),
            "rbac.user.roles.assign",
            AuditSubject::new(AuditSubjectKind::Role, Uuid::new_v4()),
            "test",
            RequestId::new("request-1").unwrap(),
            None,
        );
        let client = AuthorizationAuditContext::new(
            AuditSubject::new(AuditSubjectKind::Client, Uuid::new_v4()),
            "client.scope.set",
            AuditSubject::new(AuditSubjectKind::Permission, Uuid::new_v4()),
            "test",
            RequestId::new("request-2").unwrap(),
            None,
        );
        assert_eq!(audit_actor_type(&user), "user");
        assert_eq!(audit_actor_type(&client), "client");
    }
}
