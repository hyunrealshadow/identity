//! Derived authority fingerprints for issued authorization artifacts.
//!
//! A fingerprint is a deterministic UUID over the *semantic* authorization
//! dependencies of one user, computed inside the caller's transaction. It is
//! deliberately broader than one role or one permission: account availability,
//! every active direct/group grant path, every effective enabled role, every
//! role-permission/scope/resource dependency and the stable identity of the
//! user's authentication credentials all participate.
//!
//! Record version UUIDs are optimistic-lock tokens only. They are never read
//! here, so profile/preference edits, login counters, credential usage counters
//! and display-only role/group/permission metadata edits cannot invalidate
//! previously issued credentials.
//!
//! Credential material is never hashed. Only the stable credential OID, type
//! and expiry participate, so password hashes, TOTP secrets, passkey material,
//! recovery-code consumption and OTP replay counters stay out of the snapshot.
//!
//! The fingerprint is opaque: it is carried in JSON `_issuance_authority_fingerprint`
//! markers and compared for equality. It is never exposed through errors or logs
//! and never persisted as a version column.

use identity_domain::{
    authorization::AuthorizationVersion, rbac::deterministic_oid, user::UserOid,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, Statement};

/// Identify the actual authorization and credential state for a user.
///
/// The caller must pass the same transaction that loaded the effective
/// permissions being authorized. Callers that need a consistent read view must
/// open a repeatable-read transaction before invoking this function.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_authority_fingerprint"))]
pub(crate) async fn user_authority_fingerprint(
    txn: &DatabaseTransaction,
    user: UserOid,
) -> Result<AuthorizationVersion, DbErr> {
    let rows = txn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
WITH subject AS (
    SELECT id, oid, enabled, locked, locked_until FROM "user" WHERE oid = $1
), direct_paths AS (
    SELECT binding.oid AS binding_oid,
           role_row.id AS role_id,
           role_row.oid AS role_oid
    FROM user_role binding
    JOIN subject user_row ON user_row.id = binding.user_id
    JOIN "role" role_row ON role_row.id = binding.role_id AND role_row.enabled
    WHERE binding.enabled AND binding.revoked_at IS NULL
), group_paths AS (
    SELECT membership.oid AS membership_oid,
           user_group_row.oid AS group_oid,
           relation.oid AS binding_oid,
           role_row.id AS role_id,
           role_row.oid AS role_oid
    FROM group_membership membership
    JOIN subject user_row ON user_row.id = membership.user_id
    JOIN user_group user_group_row
      ON user_group_row.id = membership.group_id
     AND user_group_row.enabled
     AND user_group_row.deleted_at IS NULL
    JOIN group_role relation
      ON relation.group_id = user_group_row.id
     AND relation.enabled
     AND relation.revoked_at IS NULL
    JOIN "role" role_row ON role_row.id = relation.role_id AND role_row.enabled
    WHERE membership.enabled AND membership.revoked_at IS NULL
), effective_roles AS (
    SELECT role_id, role_oid FROM direct_paths
    UNION
    SELECT role_id, role_oid FROM group_paths
), dependencies AS (
    SELECT 'subject' AS kind,
           jsonb_build_array(oid, enabled, locked, locked_until) AS payload
    FROM subject
    UNION ALL
    SELECT 'direct', jsonb_build_array(binding_oid, role_oid) FROM direct_paths
    UNION ALL
    SELECT 'group',
           jsonb_build_array(membership_oid, group_oid, binding_oid, role_oid)
    FROM group_paths
    UNION ALL
    SELECT 'role', jsonb_build_array(role_oid) FROM effective_roles
    UNION ALL
    SELECT 'permission',
           jsonb_build_array(
               role_permission.oid,
               scope.oid,
               scope.code,
               scope.built_in,
               scope.enabled,
               resource.oid,
               resource.uri,
               resource.enabled
           )
    FROM effective_roles effective
    JOIN role_permission ON role_permission.role_id = effective.role_id
    JOIN scope ON scope.id = role_permission.scope_id AND scope.enabled
    JOIN resource ON resource.oid = scope.resource_id
    UNION ALL
    SELECT 'credential', jsonb_build_array(credential.oid, credential.type, credential.expires_at)
    FROM user_credential credential
    JOIN subject user_row ON user_row.id = credential.user_id
    WHERE credential.type IN ('password', 'otp', 'passkey')
)
SELECT kind, payload FROM dependencies
"#,
            [user.0.into()],
        ))
        .await?;
    if rows.is_empty() {
        return Err(DbErr::RecordNotFound(
            "authorization subject is missing".to_owned(),
        ));
    }
    let mut dependencies = Vec::with_capacity(rows.len());
    for row in rows {
        let kind = row.try_get::<String>("", "kind")?;
        let payload = row.try_get::<serde_json::Value>("", "payload")?;
        dependencies.push((kind, payload.to_string()));
    }
    dependencies.sort_unstable();
    dependencies.dedup();
    let encoded =
        serde_json::to_string(&dependencies).map_err(|error| DbErr::Custom(error.to_string()))?;
    Ok(AuthorizationVersion::from_uuid(deterministic_oid(
        &format!("identity/authorization/dependencies/v2/{encoded}"),
    )))
}
