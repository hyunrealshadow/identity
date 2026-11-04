//! Live client authorization-boundary helpers.
//!
//! There is no client-management policy row, no enable switch and no separate
//! machine grant. A client's usable ceiling is exactly its live `client_scope`
//! rows joined to canonical `scope` rows and their owning resources. The
//! fingerprint helpers are opaque semantic equality tokens used by issued
//! artifacts; record optimistic-lock versions and display metadata never
//! participate.

use identity_domain::{
    authorization::PolicyVersion, client::model::ClientOid, rbac::deterministic_oid,
};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};

/// Permanently withdraw every authorization artifact owned by one client.
///
/// `revoked_at` is coalesced rather than replaced so consumed/expired artifacts
/// keep their original fact. The `_authority_withdrawn` marker is added even to
/// already-revoked parents and is never removed. Registration access tokens
/// govern the separate client-registration endpoint; their lifecycle belongs to
/// registration rather than resource authorization.
#[tracing::instrument(
    skip_all,
    name = "db.query",
    fields(
        db.system = "postgresql",
        db.operation = "withdraw_client_authorization_artifacts"
    )
)]
pub(crate) async fn withdraw_client_authorizations<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
UPDATE client_authorization
SET revoked_at = COALESCE(revoked_at, now()),
    updated_at = now(),
    data = jsonb_set(data, '{_authority_withdrawn}', 'true'::jsonb, true)
WHERE client_id = $1 AND type <> 'registration_access_token'
"#,
        [client_id.into()],
    ))
    .await?;
    Ok(())
}

/// Share-lock the live client row for issuance and derive its boundary.
pub async fn lock_client_boundary<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
) -> Result<PolicyVersion, DbErr> {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM client WHERE id = $1 FOR SHARE",
        [client_id.into()],
    ))
    .await?
    .ok_or_else(|| DbErr::RecordNotFound("client is missing".to_owned()))?;
    let (_, fingerprint) = client_boundary_fingerprint(db, client_id).await?;
    Ok(fingerprint)
}

/// Persist a real issuance-boundary change by permanently withdrawing existing
/// credentials. The exact `client_scope` rows must be updated by the caller in
/// the same transaction.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "client_authorization_boundary.withdraw"))]
pub async fn withdraw_on_boundary_change<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
) -> Result<(), DbErr> {
    withdraw_client_authorizations(db, client_id).await
}

/// Derive the exact client authority from one statement snapshot.
///
/// Inputs participate only when they constrain issuance: client OID/protocol,
/// live `client_scope` scope OIDs/codes with their owning resource identities,
/// issuance-relevant OIDC settings and authentication/grant/response methods,
/// platform redirect targets, and stable credential OID/type/expiry/revocation.
/// Client display text, descriptions, CORS presentation, usage counters, record
/// CAS versions and timestamps are excluded. Credential secret/hash/data is
/// never read.
pub(crate) async fn client_boundary_fingerprint<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
) -> Result<(bool, PolicyVersion), DbErr> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
WITH target AS (
    SELECT c.id, c.oid, c.protocol
    FROM client c
    WHERE c.id = $1
), dependencies AS (
    SELECT 'client' AS kind,
           jsonb_build_array(target.oid, target.protocol) AS payload
    FROM target
    UNION ALL
    SELECT 'scope',
           jsonb_build_array(
               scope.oid,
               scope.code,
               membership.client_granted,
               scope.built_in,
               scope.enabled,
               resource.oid,
               resource.uri,
               resource.enabled
           )
    FROM client_scope membership
    JOIN scope ON scope.id = membership.scope_id
    LEFT JOIN resource ON resource.oid = scope.resource_id
    WHERE membership.client_id = $1
    UNION ALL
    SELECT 'oidc',
           jsonb_build_array(
               oidc.token_endpoint_auth_methods,
               oidc.token_endpoint_auth_signing_algs,
               oidc.grant_types,
               oidc.response_types,
               oidc.request_object_signing_algs,
               oidc.request_object_encryption_algs,
               oidc.request_object_encryption_encs,
               oidc.request_uris,
               oidc.subject_type,
               oidc.default_acr_values,
               oidc.default_max_age,
               oidc.require_auth_time,
               oidc.post_logout_redirect_uris,
               oidc.frontchannel_logout_uri,
               oidc.frontchannel_logout_session_required,
               oidc.backchannel_logout_uri,
               oidc.backchannel_logout_session_required,
               oidc.settings
           )
    FROM client_openid_connect oidc
    WHERE oidc.client_id = $1
    UNION ALL
    SELECT 'platform', jsonb_build_array(platform.platform, platform.redirect_uris)
    FROM client_openid_connect_platform platform
    WHERE platform.client_id = $1
    UNION ALL
    SELECT 'credential',
           jsonb_build_array(
               credential.oid,
               credential.type,
               credential.expires_at,
               credential.revoked_at
           )
    FROM client_openid_connect_credential credential
    WHERE credential.client_id = $1
)
SELECT true AS present,
       COALESCE(
           jsonb_agg(
               jsonb_build_array(dependencies.kind, dependencies.payload)
               ORDER BY dependencies.kind, dependencies.payload::text
           ) FILTER (WHERE dependencies.kind IS NOT NULL),
           '[]'::jsonb
       ) AS dependencies
FROM target
LEFT JOIN dependencies ON true
GROUP BY target.id
"#,
            [client_id.into()],
        ))
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("client is missing".to_owned()))?;
    let dependencies = row.try_get::<serde_json::Value>("", "dependencies")?;
    let encoded =
        serde_json::to_string(&dependencies).map_err(|error| DbErr::Custom(error.to_string()))?;
    Ok((
        true,
        PolicyVersion::from_uuid(deterministic_oid(&format!(
            "identity/authorization/client-boundary/v2/{client_id}/{encoded}"
        ))),
    ))
}

/// Exact client-scope codes for one target resource.
///
/// Protocol scopes (`resource_id IS NULL`) apply globally, while API scopes are
/// included only when their owning resource is the target. A same-code scope in
/// another resource is never returned. With `client_granted_only`, only rows
/// granted to the client itself qualify; other rows merely bound requests made
/// on behalf of a user.
pub(crate) async fn client_scope_codes<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
    resource_uri: &str,
    client_granted_only: bool,
) -> Result<Vec<String>, DbErr> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT scope.code
FROM client_scope membership
JOIN scope ON scope.id = membership.scope_id AND scope.enabled = true
LEFT JOIN resource ON resource.oid = scope.resource_id
WHERE membership.client_id = $1
  AND ($3 = false OR membership.client_granted)
  AND (
        scope.resource_id IS NULL
        OR (resource.enabled = true AND resource.uri = $2)
      )
ORDER BY scope.code
"#,
            [
                client_id.into(),
                resource_uri.to_owned().into(),
                client_granted_only.into(),
            ],
        ))
        .await?;
    rows.into_iter()
        .map(|row| row.try_get::<String>("", "code"))
        .collect()
}

/// Resolve a client OID to its internal id.
pub(crate) async fn client_id_by_oid<C: ConnectionTrait>(
    db: &C,
    client_oid: ClientOid,
) -> Result<Option<i64>, DbErr> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM client WHERE oid = $1",
            [client_oid.into()],
        ))
        .await?;
    row.map(|row| row.try_get::<i64>("", "id")).transpose()
}

#[cfg(test)]
mod tests {
    use identity_domain::authorization::policy_fingerprint;
    use uuid::Uuid;

    #[test]
    fn policy_fingerprint_is_not_a_record_version_and_is_stable() {
        let first = policy_fingerprint();
        let second = policy_fingerprint();
        assert_eq!(first, second);
        assert_ne!(first.as_uuid(), Uuid::nil());
        assert_eq!(first.as_uuid().get_version_num(), 8);
    }
}
