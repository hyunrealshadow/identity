//! Live scope authority for a client principal at the first-party resource.

use identity_domain::{
    authorization::{ClientScopeAuthority, ManagementScope, is_trusted_management_permission},
    client::model::ClientOid,
};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};
use std::collections::BTreeSet;
use uuid::Uuid;

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "load_client_scope_authority"))]
pub(crate) async fn load_client_scope_authority<C: ConnectionTrait>(
    db: &C,
    client_oid: ClientOid,
) -> Result<Option<ClientScopeAuthority>, DbErr> {
    let Some(client_id) =
        crate::database::client_authorization_boundary::client_id_by_oid(db, client_oid).await?
    else {
        return Ok(None);
    };
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT s.oid, s.code FROM client_scope cs \
         JOIN scope s ON s.id = cs.scope_id AND s.enabled AND s.built_in \
         JOIN resource r ON r.oid = s.resource_id AND r.enabled \
         WHERE cs.client_id = $1 AND r.uri = 'urn:identity:graphql' ORDER BY s.code",
            [client_id.into()],
        ))
        .await?;
    let mut permissions = BTreeSet::new();
    for row in rows {
        let code = row.try_get::<String>("", "code")?;
        if let Some(scope) = ManagementScope::from_name(&code) {
            if !is_trusted_management_permission(scope, row.try_get::<Uuid>("", "oid")?, &code) {
                return Err(DbErr::Type("invalid built-in scope identity".to_owned()));
            }
            permissions.insert(scope);
        }
    }
    let (_, boundary) =
        crate::database::client_authorization_boundary::client_boundary_fingerprint(db, client_id)
            .await?;
    Ok(Some(ClientScopeAuthority {
        client_oid,
        permissions,
        boundary,
    }))
}

/// Lock the actual configured client while issuance keeps its existing active,
/// session, user and permanent-revocation checks. No management policy exists.
#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "lock_live_client_boundary"))]
pub(crate) async fn lock_live_client_boundary<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
) -> Result<(bool, identity_domain::authorization::PolicyVersion), DbErr> {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM client WHERE id = $1 FOR SHARE",
        [client_id.into()],
    ))
    .await?
    .ok_or_else(|| DbErr::RecordNotFound("client is missing".to_owned()))?;
    let configured = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT client_id FROM client_openid_connect WHERE client_id = $1 FOR SHARE",
            [client_id.into()],
        ))
        .await?
        .is_some();
    let (_, fingerprint) =
        crate::database::client_authorization_boundary::client_boundary_fingerprint(db, client_id)
            .await?;
    Ok((configured, fingerprint))
}
