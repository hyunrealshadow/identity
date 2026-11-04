use std::sync::Arc;

use async_trait::async_trait;
use identity_domain::{
    authorization::PolicyVersion,
    client::model::ClientOid,
    client_authorization::AccessTokenPrincipal,
    openid_connect::resource::{
        OAuthResource, OAuthResourceRepository, OAuthResourceRepositoryError,
    },
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, Statement,
};
use uuid::Uuid;

use crate::database::client_authorization_boundary;

/// Permanently withdraw every authorization artifact whose target is exactly
/// this resource.
///
/// Artifacts identify their business resource through the serialized
/// `management` business snapshot (`resource_oid`/`resource_uri`) or through
/// the actual target URI list carried by access tokens, codes, refresh tokens,
/// device requests/relations, queued authorization requests (nested
/// `request.resources`) and pushed authorization requests (nested
/// `parameters.resources`). Consumed single-use parents and machine
/// `client_credentials` access tokens are updated too: the durable
/// `_authority_withdrawn` marker makes an enable/restore or semantic ABA cycle
/// unable to revive them. Matching is by exact OID/URI only, so credentials of
/// another client or resource are never touched.
#[tracing::instrument(
    skip_all,
    name = "db.query",
    fields(
        db.system = "postgresql",
        db.operation = "withdraw_resource_authorization_artifacts"
    )
)]
pub(crate) async fn withdraw_resource_authorization_artifacts(
    txn: &DatabaseTransaction,
    resource_oid: Uuid,
) -> Result<(), DbErr> {
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
WITH target AS (
    SELECT oid, uri FROM resource WHERE oid = $1
)
UPDATE client_authorization artifact
SET revoked_at = COALESCE(artifact.revoked_at, now()),
    updated_at = now(),
    data = jsonb_set(artifact.data, '{_authority_withdrawn}', 'true'::jsonb, true)
FROM target
WHERE artifact.data->'management'->>'resource_oid' = target.oid::text
   OR artifact.data->'management'->>'resource_uri' = target.uri
   OR artifact.data->>'resource_oid' = target.oid::text
   OR artifact.data->>'resource_uri' = target.uri
   OR jsonb_exists(artifact.data->'resources', target.uri)
   OR jsonb_exists(artifact.data->'request'->'resources', target.uri)
   OR jsonb_exists(artifact.data->'parameters'->'resources', target.uri)
"#,
        [resource_oid.into()],
    ))
    .await?;
    Ok(())
}

pub struct OAuthResourceRepositoryImpl {
    db: Arc<DatabaseConnection>,
}

impl OAuthResourceRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db: Arc::new(db) }
    }
}

fn storage_error(error: DbErr) -> OAuthResourceRepositoryError {
    OAuthResourceRepositoryError(error.to_string())
}

async fn resource_oid<C: ConnectionTrait>(
    db: &C,
    uri: &str,
) -> Result<Option<Uuid>, OAuthResourceRepositoryError> {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT oid FROM resource WHERE uri = $1",
        [uri.into()],
    ))
    .await
    .map_err(storage_error)?
    .map(|row| row.try_get::<Uuid>("", "oid").map_err(storage_error))
    .transpose()
}

#[async_trait]
impl OAuthResourceRepository for OAuthResourceRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "oauth_resource.find_by_uri"))]
    async fn find_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<OAuthResource>, OAuthResourceRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT oid, uri, enabled FROM resource WHERE uri = $1",
                [uri.into()],
            ))
            .await
            .map_err(storage_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let resource_oid = row.try_get::<Uuid>("", "oid").map_err(storage_error)?;
        let enabled = row.try_get::<bool>("", "enabled").map_err(storage_error)?;
        let scope_rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT code FROM \"scope\" \
                 WHERE resource_id = (SELECT oid FROM resource WHERE oid = $1) \
                   AND enabled = true \
                 ORDER BY code",
                [resource_oid.into()],
            ))
            .await
            .map_err(storage_error)?;
        let scopes = scope_rows
            .into_iter()
            .map(|row| row.try_get::<String>("", "code").map_err(storage_error))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(OAuthResource {
            uri: uri.to_owned(),
            scopes,
            enabled,
        }))
    }

    async fn client_scope_codes(
        &self,
        client: ClientOid,
        resource_uri: &str,
        principal: AccessTokenPrincipal,
    ) -> Result<Option<Vec<String>>, OAuthResourceRepositoryError> {
        let Some(client_id) =
            client_authorization_boundary::client_id_by_oid(self.db.as_ref(), client)
                .await
                .map_err(storage_error)?
        else {
            return Err(OAuthResourceRepositoryError("client not found".to_owned()));
        };
        if resource_oid(self.db.as_ref(), resource_uri)
            .await?
            .is_none()
        {
            return Err(OAuthResourceRepositoryError(
                "resource not found".to_owned(),
            ));
        }
        client_authorization_boundary::client_scope_codes(
            self.db.as_ref(),
            client_id,
            resource_uri,
            principal == AccessTokenPrincipal::Client,
        )
        .await
        .map(Some)
        .map_err(storage_error)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "oauth_resource.client_protocol_scopes"))]
    async fn client_protocol_scope_codes(
        &self,
        client: ClientOid,
    ) -> Result<Option<Vec<String>>, OAuthResourceRepositoryError> {
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT s.code FROM client_scope cs \
             JOIN client c ON c.id = cs.client_id \
             JOIN scope s ON s.id = cs.scope_id \
             WHERE c.oid = $1 AND s.resource_id IS NULL AND s.enabled = true \
             ORDER BY s.code",
                [client.into()],
            ))
            .await
            .map_err(storage_error)?;
        rows.into_iter()
            .map(|row| row.try_get::<String>("", "code").map_err(storage_error))
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    async fn client_authority_fingerprint(
        &self,
        client: ClientOid,
    ) -> Result<Option<PolicyVersion>, OAuthResourceRepositoryError> {
        let Some(client_id) =
            client_authorization_boundary::client_id_by_oid(self.db.as_ref(), client)
                .await
                .map_err(storage_error)?
        else {
            return Err(OAuthResourceRepositoryError("client not found".to_owned()));
        };
        let (_, fingerprint) =
            client_authorization_boundary::client_boundary_fingerprint(self.db.as_ref(), client_id)
                .await
                .map_err(storage_error)?;
        Ok(Some(fingerprint))
    }
}
