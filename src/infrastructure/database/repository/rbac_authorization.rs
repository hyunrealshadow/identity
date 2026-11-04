//! SeaORM implementation of business RBAC token authorization reads.
//!
//! Every public read runs in one repeatable-read transaction so the resource
//! boundary fingerprint, derived user authority fingerprint, binding identities,
//! semantic role dependency identities, memberships and enabled canonical scope
//! rows all belong to the same authoritative snapshot. Record version UUIDs
//! remain optimistic-lock tokens and are not credential authority; resource and
//! scope fingerprints are derived from semantic fields only and therefore
//! exclude display names, descriptions and serialized versions. Missing users,
//! resources or scope rows fail closed.

use std::collections::BTreeSet;

use chrono::Utc;
use identity_domain::{
    authorization::ids::AuthorizationVersion,
    client::model::ClientOid,
    rbac::{
        LocalizedMetadata, RbacAuthorizationError, RbacAuthorizationRepository,
        RbacAuthorizationState, RbacResourceState,
        authorization::{BusinessAuthorizationSnapshot, validate_business_snapshot},
        deterministic_oid,
        ids::{
            GroupMembershipOid, GroupOid, GroupRoleBindingOid, ResourceOid, ResourcePermissionOid,
            RoleOid, RolePermissionOid, UserRoleBindingOid,
        },
        model::{
            GroupRolePath, PermissionCode, ResourcePermission, Role, RolePermission,
            UserRoleBinding,
        },
    },
    user::UserOid,
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement, TransactionTrait,
    entity::prelude::DateTimeWithTimeZone,
};
use serde_json::Value;
use uuid::Uuid;

use super::localized::{self, LocalizedJsonError};
use crate::database::{
    authority_snapshot::user_authority_fingerprint, client_authorization_boundary,
};

/// Read-only business RBAC adapter.
pub struct RbacAuthorizationRepositoryImpl {
    db: DatabaseConnection,
}

impl RbacAuthorizationRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage(error: DbErr) -> RbacAuthorizationError {
    RbacAuthorizationError::Storage(Box::new(error))
}

fn corrupt() -> RbacAuthorizationError {
    RbacAuthorizationError::CorruptRecord
}

fn localized_error(_error: LocalizedJsonError) -> RbacAuthorizationError {
    corrupt()
}

fn localized_metadata(
    row: &sea_orm::QueryResult,
) -> Result<LocalizedMetadata, RbacAuthorizationError> {
    localized::decode_metadata(
        row.try_get::<Value>("", "names").map_err(storage)?,
        row.try_get::<Value>("", "descriptions").map_err(storage)?,
    )
    .map_err(localized_error)
}

fn authorization_version(value: Uuid) -> AuthorizationVersion {
    AuthorizationVersion::from_uuid(value)
}

/// Start one consistent snapshot read. `SET TRANSACTION` is issued before the
/// first query inside the transaction.
async fn read_transaction(
    db: &DatabaseConnection,
) -> Result<sea_orm::DatabaseTransaction, RbacAuthorizationError> {
    let txn = db.begin().await.map_err(storage)?;
    txn.execute_raw(Statement::from_string(
        DbBackend::Postgres,
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
    ))
    .await
    .map_err(storage)?;
    Ok(txn)
}

/// Derive the opaque resource-boundary fingerprint from semantic resource and
/// canonical scope facts only.
///
/// Record versions are deliberately absent: they are optimistic-lock tokens,
/// not authorization identity. Display metadata (name, localized names and
/// descriptions) is also absent, so a rename does not revoke credentials. The
/// resource identity/URI/enabled flag and every enabled canonical scope's
/// OID/code/built-in flag participate.
fn resource_boundary_fingerprint(
    resource_oid: ResourceOid,
    resource_uri: &str,
    enabled: bool,
    permissions: &[ResourcePermission],
) -> Result<AuthorizationVersion, RbacAuthorizationError> {
    let mut permission_bounds = permissions
        .iter()
        .map(|permission| {
            (
                permission.oid.0.to_string(),
                permission.code.as_str().to_owned(),
                permission.scope.clone(),
                permission.built_in,
            )
        })
        .collect::<Vec<_>>();
    permission_bounds.sort();
    let encoded = serde_json::to_string(&serde_json::json!([
        resource_oid.0.to_string(),
        resource_uri,
        enabled,
        permission_bounds,
    ]))
    .map_err(|_| corrupt())?;
    Ok(authorization_version(deterministic_oid(&format!(
        "identity/authorization/resource-boundary/v2/{encoded}"
    ))))
}

async fn load_resource_state<C: ConnectionTrait>(
    db: &C,
    resource_uri: &str,
) -> Result<RbacResourceState, RbacAuthorizationError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT r.oid AS resource_oid,
       r.uri AS resource_uri,
       r.enabled AS resource_enabled
FROM resource r
WHERE r.uri = $1
"#,
            [resource_uri.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or(RbacAuthorizationError::ResourceNotFound)?;

    let resource_oid = ResourceOid(row.try_get::<Uuid>("", "resource_oid").map_err(storage)?);
    let resource_uri = row.try_get::<String>("", "resource_uri").map_err(storage)?;
    let enabled = row
        .try_get::<bool>("", "resource_enabled")
        .map_err(storage)?;
    let permission_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT scope.oid AS permission_oid,
       scope.code AS permission_code,
       scope.name AS name,
       scope.description AS description,
       scope.built_in AS built_in,
       scope.names AS names,
       scope.descriptions AS descriptions,
       scope.enabled AS enabled,
       scope.version AS version,
       scope.created_at AS created_at,
       scope.updated_at AS updated_at
FROM scope
JOIN resource ON resource.oid = scope.resource_id
WHERE resource.uri = $1 AND scope.enabled = true
ORDER BY scope.code
"#,
            [resource_uri.clone().into()],
        ))
        .await
        .map_err(storage)?;

    let mut permissions = Vec::with_capacity(permission_rows.len());
    for row in permission_rows {
        let permission_oid =
            ResourcePermissionOid(row.try_get("", "permission_oid").map_err(storage)?);
        let code = PermissionCode::parse(
            row.try_get::<String>("", "permission_code")
                .map_err(storage)?,
        )
        .map_err(|_| corrupt())?;
        let scope = code.as_str().to_owned();
        let description = row
            .try_get::<Option<String>>("", "description")
            .map_err(storage)?;
        let enabled = row.try_get::<bool>("", "enabled").map_err(storage)?;
        let version = authorization_version(row.try_get::<Uuid>("", "version").map_err(storage)?);
        let created_at = row
            .try_get::<DateTimeWithTimeZone>("", "created_at")
            .map_err(storage)?
            .with_timezone(&Utc);
        let updated_at = row
            .try_get::<Option<DateTimeWithTimeZone>>("", "updated_at")
            .map_err(storage)?
            .map(|value| value.with_timezone(&Utc));
        permissions.push(ResourcePermission {
            oid: permission_oid,
            name: row.try_get::<String>("", "name").map_err(storage)?,
            resource_oid,
            code,
            scope,
            description,
            built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
            metadata: localized_metadata(&row)?,
            enabled,
            version,
            created_at,
            updated_at,
        });
    }

    let policy_version =
        resource_boundary_fingerprint(resource_oid, &resource_uri, enabled, &permissions)?;
    let accepted_scopes = permissions
        .iter()
        .map(|permission| permission.scope.clone())
        .collect();

    Ok(RbacResourceState {
        resource_oid,
        resource_uri,
        policy_version,
        enabled,
        accepted_scopes,
        permissions,
    })
}

struct CurrentUser {
    id: i64,
    oid: UserOid,
    enabled: bool,
    locked: bool,
}

async fn load_user<C: ConnectionTrait>(
    db: &C,
    user_oid: UserOid,
) -> Result<CurrentUser, RbacAuthorizationError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT u.id AS user_id,
       u.oid AS user_oid,
       u.enabled AS enabled,
       u.locked AS locked,
       u.locked_until AS locked_until
FROM "user" u
WHERE u.oid = $1
"#,
            [user_oid.0.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or(RbacAuthorizationError::UserNotFound)?;

    let enabled = row.try_get::<bool>("", "enabled").map_err(storage)?;
    let locked = row.try_get::<bool>("", "locked").map_err(storage)?;
    let locked_until = row
        .try_get::<Option<DateTimeWithTimeZone>>("", "locked_until")
        .map_err(storage)?
        .map(|value| value.with_timezone(&Utc));
    let now = Utc::now();
    // Match login semantics: an expired temporary lock no longer blocks the
    // user, while a permanent lock (or one that has not expired) does.
    let effectively_locked = locked && locked_until.is_none_or(|until| until > now);

    Ok(CurrentUser {
        id: row.try_get("", "user_id").map_err(storage)?,
        oid: UserOid(row.try_get("", "user_oid").map_err(storage)?),
        enabled,
        locked: effectively_locked,
    })
}

async fn load_bindings<C: ConnectionTrait>(
    db: &C,
    user_id: i64,
) -> Result<Vec<UserRoleBinding>, RbacAuthorizationError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT binding.oid AS binding_oid,
       binding.granted_by_user_id AS granted_by_user_id,
       binding.reason AS reason,
       binding.enabled AS enabled,
       binding.revoked_at AS revoked_at,
       binding.version AS version,
       binding.created_at AS created_at,
       binding.updated_at AS updated_at,
       user_row.oid AS user_oid,
       role_row.oid AS role_oid,
       granted_by.oid AS granted_by_oid
FROM user_role_binding binding
JOIN "user" user_row ON user_row.id = binding.user_id
JOIN role role_row ON role_row.id = binding.role_id
LEFT JOIN "user" granted_by ON granted_by.id = binding.granted_by_user_id
WHERE binding.user_id = $1
  AND binding.enabled = true
  AND binding.revoked_at IS NULL
ORDER BY binding.id
"#,
            [user_id.into()],
        ))
        .await
        .map_err(storage)?;

    let mut bindings = Vec::with_capacity(rows.len());
    for row in rows {
        let revoked_at = row
            .try_get::<Option<DateTimeWithTimeZone>>("", "revoked_at")
            .map_err(storage)?
            .map(|value| value.with_timezone(&Utc));
        let created_at = row
            .try_get::<DateTimeWithTimeZone>("", "created_at")
            .map_err(storage)?
            .with_timezone(&Utc);
        let updated_at = row
            .try_get::<Option<DateTimeWithTimeZone>>("", "updated_at")
            .map_err(storage)?
            .map(|value| value.with_timezone(&Utc));
        bindings.push(UserRoleBinding {
            oid: UserRoleBindingOid(row.try_get("", "binding_oid").map_err(storage)?),
            user_oid: UserOid(row.try_get("", "user_oid").map_err(storage)?),
            role_oid: RoleOid(row.try_get("", "role_oid").map_err(storage)?),
            granted_by_user_oid: row
                .try_get::<Option<Uuid>>("", "granted_by_oid")
                .map_err(storage)?
                .map(UserOid),
            reason: row.try_get("", "reason").map_err(storage)?,
            enabled: row.try_get("", "enabled").map_err(storage)?,
            revoked_at,
            version: authorization_version(row.try_get("", "version").map_err(storage)?),
            created_at,
            updated_at,
        });
    }
    Ok(bindings)
}

/// Active group paths for one user. Membership and group-role relation keep
/// their real identities; the reader never fabricates direct bindings.
async fn load_group_paths<C: ConnectionTrait>(
    db: &C,
    user_id: i64,
) -> Result<Vec<GroupRolePath>, RbacAuthorizationError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT membership.oid AS membership_oid,
       user_group_row.oid AS group_oid,
       group_relation.oid AS group_role_binding_oid,
       role_row.oid AS role_oid
FROM group_membership membership
JOIN user_group user_group_row
  ON user_group_row.id = membership.group_id AND user_group_row.enabled = true
JOIN group_role_binding group_relation
  ON group_relation.group_id = user_group_row.id
 AND group_relation.enabled = true
 AND group_relation.revoked_at IS NULL
JOIN role role_row ON role_row.id = group_relation.role_id AND role_row.enabled = true
WHERE membership.user_id = $1
  AND membership.enabled = true
  AND membership.revoked_at IS NULL
ORDER BY user_group_row.id, group_relation.id, membership.id
"#,
            [user_id.into()],
        ))
        .await
        .map_err(storage)?;
    let mut paths = Vec::with_capacity(rows.len());
    for row in rows {
        paths.push(GroupRolePath {
            membership_oid: GroupMembershipOid(
                row.try_get::<Uuid>("", "membership_oid").map_err(storage)?,
            ),
            group_oid: GroupOid(row.try_get::<Uuid>("", "group_oid").map_err(storage)?),
            group_role_binding_oid: GroupRoleBindingOid(
                row.try_get::<Uuid>("", "group_role_binding_oid")
                    .map_err(storage)?,
            ),
            role_oid: RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?),
        });
    }
    Ok(paths)
}

async fn load_roles<C: ConnectionTrait>(
    db: &C,
    user_id: i64,
) -> Result<Vec<Role>, RbacAuthorizationError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT role_row.oid AS role_oid,
       role_row.name AS name,
       role_row.description AS description,
       role_row.built_in AS built_in,
       role_row.names AS names, role_row.descriptions AS descriptions,
       role_row.enabled AS enabled,
       role_row.created_at AS created_at,
       role_row.updated_at AS updated_at,
       role_row.version AS version
FROM role role_row
JOIN (
    SELECT binding.role_id
    FROM user_role_binding binding
    WHERE binding.user_id = $1
      AND binding.enabled = true
      AND binding.revoked_at IS NULL
    UNION
    SELECT group_relation.role_id
    FROM group_membership membership
    JOIN user_group user_group_row
      ON user_group_row.id = membership.group_id AND user_group_row.enabled = true
    JOIN group_role_binding group_relation
      ON group_relation.group_id = user_group_row.id
     AND group_relation.enabled = true
     AND group_relation.revoked_at IS NULL
    WHERE membership.user_id = $1
      AND membership.enabled = true
      AND membership.revoked_at IS NULL
) effective_role ON effective_role.role_id = role_row.id
WHERE role_row.enabled = true
ORDER BY role_row.id
"#,
            [user_id.into()],
        ))
        .await
        .map_err(storage)?;

    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        let created_at = row
            .try_get::<DateTimeWithTimeZone>("", "created_at")
            .map_err(storage)?
            .with_timezone(&Utc);
        let updated_at = row
            .try_get::<Option<DateTimeWithTimeZone>>("", "updated_at")
            .map_err(storage)?
            .map(|value| value.with_timezone(&Utc));
        let oid = RoleOid(row.try_get("", "role_oid").map_err(storage)?);
        roles.push(Role {
            oid,
            name: row.try_get("", "name").map_err(storage)?,
            description: row.try_get("", "description").map_err(storage)?,
            built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
            metadata: localized_metadata(&row)?,
            enabled: row.try_get("", "enabled").map_err(storage)?,
            version: authorization_version(row.try_get::<Uuid>("", "version").map_err(storage)?),
            created_at,
            updated_at,
        });
    }
    Ok(roles)
}

async fn load_memberships<C: ConnectionTrait>(
    db: &C,
    resource_oid: ResourceOid,
) -> Result<Vec<RolePermission>, RbacAuthorizationError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT membership.oid AS membership_oid,
       role_row.oid AS role_oid,
       scope.oid AS permission_oid,
       membership.created_at AS created_at
FROM role_permission membership
JOIN role role_row ON role_row.id = membership.role_id
JOIN scope ON scope.id = membership.scope_id AND scope.enabled = true
JOIN resource ON resource.oid = scope.resource_id
WHERE resource.oid = $1
  AND role_row.enabled = true
ORDER BY membership.id
"#,
            [resource_oid.0.into()],
        ))
        .await
        .map_err(storage)?;

    let mut memberships = Vec::with_capacity(rows.len());
    for row in rows {
        let created_at = row
            .try_get::<DateTimeWithTimeZone>("", "created_at")
            .map_err(storage)?
            .with_timezone(&Utc);
        memberships.push(RolePermission {
            oid: RolePermissionOid(row.try_get("", "membership_oid").map_err(storage)?),
            role_oid: RoleOid(row.try_get("", "role_oid").map_err(storage)?),
            permission_oid: ResourcePermissionOid(
                row.try_get("", "permission_oid").map_err(storage)?,
            ),
            created_at,
        });
    }
    Ok(memberships)
}

async fn load_state(
    txn: &sea_orm::DatabaseTransaction,
    user: Option<UserOid>,
    resource_uri: &str,
) -> Result<RbacAuthorizationState, RbacAuthorizationError> {
    let resource = load_resource_state(txn, resource_uri).await?;
    match user {
        Some(user_oid) => {
            let current_user = load_user(txn, user_oid).await?;
            let bindings = load_bindings(txn, current_user.id).await?;
            let group_paths = load_group_paths(txn, current_user.id).await?;
            let roles = load_roles(txn, current_user.id).await?;
            let memberships = load_memberships(txn, resource.resource_oid).await?;
            // Derived from the same repeatable-read view as the permission
            // rows above. The user record version is intentionally not used.
            let authority_fingerprint = user_authority_fingerprint(txn, current_user.oid)
                .await
                .map_err(storage)?;
            Ok(RbacAuthorizationState {
                resource,
                user_oid: Some(current_user.oid),
                user_authorization_version: Some(authority_fingerprint),
                user_enabled: Some(current_user.enabled),
                user_locked: Some(current_user.locked),
                bindings,
                group_paths,
                roles,
                memberships,
            })
        }
        None => Ok(RbacAuthorizationState {
            resource,
            user_oid: None,
            user_authorization_version: None,
            user_enabled: None,
            user_locked: None,
            bindings: Vec::new(),
            group_paths: Vec::new(),
            roles: Vec::new(),
            memberships: Vec::new(),
        }),
    }
}

#[async_trait::async_trait]
impl RbacAuthorizationRepository for RbacAuthorizationRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "rbac_authorization.resource_state"))]
    async fn resource_state(
        &self,
        resource_uri: &str,
    ) -> Result<RbacResourceState, RbacAuthorizationError> {
        let txn = read_transaction(&self.db).await?;
        let state = load_resource_state(&txn, resource_uri).await;
        match state {
            Ok(state) => {
                txn.commit().await.map_err(storage)?;
                Ok(state)
            }
            Err(error) => {
                let _ = txn.rollback().await;
                Err(error)
            }
        }
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "rbac_authorization.authorization_state"))]
    async fn authorization_state(
        &self,
        user: UserOid,
        resource_uri: &str,
    ) -> Result<RbacAuthorizationState, RbacAuthorizationError> {
        let txn = read_transaction(&self.db).await?;
        let state = load_state(&txn, Some(user), resource_uri).await;
        match state {
            Ok(state) => {
                txn.commit().await.map_err(storage)?;
                Ok(state)
            }
            Err(error) => {
                let _ = txn.rollback().await;
                Err(error)
            }
        }
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "rbac_authorization.validate_snapshot"))]
    async fn validate_snapshot(
        &self,
        snapshot: &BusinessAuthorizationSnapshot,
    ) -> Result<RbacAuthorizationState, RbacAuthorizationError> {
        let txn = read_transaction(&self.db).await?;
        let state = load_state(&txn, snapshot.user_oid, &snapshot.resource_uri).await;
        let state = match state {
            Ok(state) => state,
            Err(error) => {
                let _ = txn.rollback().await;
                return Err(error);
            }
        };
        if let Err(error) = validate_business_snapshot(snapshot, &state) {
            let _ = txn.rollback().await;
            return Err(RbacAuthorizationError::Snapshot(error));
        }
        txn.commit().await.map_err(storage)?;
        Ok(state)
    }

    async fn client_scope_codes(
        &self,
        client: ClientOid,
        resource_uri: &str,
    ) -> Result<BTreeSet<String>, RbacAuthorizationError> {
        let txn = read_transaction(&self.db).await?;
        let result = async {
            let client_id = client_authorization_boundary::client_id_by_oid(&txn, client)
                .await
                .map_err(storage)?
                .ok_or(RbacAuthorizationError::ResourceNotFound)?;
            let present = txn
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT 1 FROM resource WHERE uri = $1",
                    [resource_uri.into()],
                ))
                .await
                .map_err(storage)?;
            if present.is_none() {
                return Err(RbacAuthorizationError::ResourceNotFound);
            }
            client_authorization_boundary::client_scope_codes(&txn, client_id, resource_uri, false)
                .await
                .map_err(storage)
        }
        .await;
        match result {
            Ok(codes) => {
                txn.commit().await.map_err(storage)?;
                Ok(codes.into_iter().collect())
            }
            Err(error) => {
                let _ = txn.rollback().await;
                Err(error)
            }
        }
    }
}
