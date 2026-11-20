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
    TransactionTrait,
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
        let current = load_user_permission_authority(&txn, UserOid(snapshot.grant_oid)).await;
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
