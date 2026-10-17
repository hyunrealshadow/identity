use crate::database::{
    entity::{
        client, client::Entity as ClientEntity, client_authorization,
        client_authorization::Entity as ClientAuthorizationEntity, session,
        session::Entity as SessionEntity,
    },
    repository::{client_authorization_query as query, shared::lock_session},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::error::ErrorContext;
use identity_domain::{
    auth::{SessionOid, SessionStatus},
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationRepository,
        ClientAuthorizationRepositoryError, ClientAuthorizationType, ConsentState,
        PushedAuthorizationRequestData, SelectionSource,
    },
    openid_connect::ScopeSet,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr,
    EntityTrait, FromQueryResult, QueryFilter, Set, TransactionTrait,
};
use serde_json::from_value;
use std::error::Error;
use uuid::Uuid;

mod consent;
mod mapping;
mod request_interaction;
mod token_revocation;

pub(super) use mapping::{serialize_data, to_domain};
use token_revocation::lock_refresh_family;

fn query_failed(
    operation: &'static str,
    error: impl Error + Send + Sync + 'static,
) -> ClientAuthorizationRepositoryError {
    ClientAuthorizationRepositoryError::QueryFailed(Box::new(ErrorContext::new(operation, error)))
}

fn query_error<E: Error + Send + Sync + 'static>(
    operation: &'static str,
) -> impl FnOnce(E) -> ClientAuthorizationRepositoryError {
    move |error| query_failed(operation, error)
}

pub struct ClientAuthorizationRepositoryImpl {
    db: DatabaseConnection,
}

impl ClientAuthorizationRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

/// Marks one batch of expired authorizations without deleting their records.
/// The caller repeats until fewer than the batch limit were updated.
pub(crate) async fn expire_due_authorizations_batch(
    db: &DatabaseConnection,
) -> Result<u64, ErrorContext> {
    Ok(db
        .execute(&query::expiration_batch())
        .await
        .map_err(|error| {
            ErrorContext::new(
                "client_authorization.expire_due_authorizations_batch",
                error,
            )
        })?
        .rows_affected())
}

#[async_trait]
impl ClientAuthorizationRepository for ClientAuthorizationRepositoryImpl {
    async fn consume_pushed_authorization_request(
        &self,
        digest: &str,
        client_oid: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<PushedAuthorizationRequestData>, ClientAuthorizationRepositoryError> {
        let row = client_authorization::Model::find_by_statement(
            DatabaseBackend::Postgres.build(&query::consume_par(digest, client_oid, now)),
        )
        .one(&self.db)
        .await
        .map_err(query_error(
            "client_authorization.consume_pushed_authorization_request",
        ))?;
        row.map(|row| {
            from_value::<PushedAuthorizationRequestData>(row.data).map_err(query_error(
                "client_authorization.consume_pushed_authorization_request",
            ))
        })
        .transpose()
    }
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "create"))]
    async fn create(
        &self,
        client_oid: ClientOid,
        data: ClientAuthorizationData,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
        let type_ = data.authorization_type();
        let session_oid = match &data {
            ClientAuthorizationData::AuthorizationCode(data) => Some(data.session_oid),
            ClientAuthorizationData::AccessToken(data) => data.session_oid,
            ClientAuthorizationData::RefreshToken(data) => data.session_oid,
            _ => None,
        };
        let family_refresh_oid = match &data {
            ClientAuthorizationData::RefreshToken(refresh) => refresh.rotated_from.as_deref(),
            ClientAuthorizationData::AccessToken(access) => access.refresh_token_oid.as_deref(),
            _ => None,
        }
        .map(Uuid::parse_str)
        .transpose()
        .map_err(query_error("client_authorization.create"))?;
        let transaction = self
            .db
            .begin()
            .await
            .map_err(query_error("client_authorization.create"))?;
        if let Some(session_oid) = session_oid {
            lock_session(&transaction, session_oid)
                .await
                .map_err(query_error("client_authorization.create"))?;
            let now = Utc::now();
            let session_available = SessionEntity::find()
                .filter(session::Column::Oid.eq(Uuid::from(session_oid)))
                .filter(session::Column::Status.eq(SessionStatus::ACTIVE.as_str()))
                .filter(session::Column::RevokedAt.is_null())
                .filter(session::Column::ExpiresAt.gt(now))
                .one(&transaction)
                .await
                .map_err(query_error("client_authorization.create"))?
                .is_some();
            if !session_available {
                return Err(query_failed(
                    "client_authorization.create",
                    DbErr::RecordNotFound(format!(
                        "session {} is not active",
                        Uuid::from(session_oid)
                    )),
                ));
            }
        }
        if let Some(parent_oid) = family_refresh_oid {
            lock_refresh_family(&transaction, parent_oid, client_oid, true).await?;
        }
        let client_model = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&transaction)
            .await
            .map_err(query_error("client_authorization.create"))?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.create",
                    DbErr::RecordNotFound(format!("client {client_oid} not found")),
                )
            })?;

        let now = Utc::now();
        let data = serialize_data(&data)?;
        let model = client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(Uuid::new_v4()),
            client_id: Set(client_model.id),
            r#type: Set(type_.to_string()),
            data: Set(data),
            expires_at: Set(expires_at.into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            is_expired: Set(expires_at <= now),
            created_at: Set(now.into()),
            updated_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(query_error("client_authorization.create"))?;
        transaction
            .commit()
            .await
            .map_err(query_error("client_authorization.create"))?;
        to_domain(model, client_oid)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_oid"))]
    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError> {
        let Some((request_model, Some(client_model))) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(query_error("client_authorization.find_by_oid"))?
        else {
            return Ok(None);
        };

        Ok(Some(to_domain(request_model, client_model.oid)?))
    }

    async fn update_authorization_request_selection(
        &self,
        oid: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        request_interaction::update_authorization_request_selection(
            &self.db,
            oid,
            session_oid,
            user_oid,
            protected_session_id,
            source,
        )
        .await
    }

    async fn mark_authorization_request_completed(
        &self,
        oid: Uuid,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        request_interaction::mark_authorization_request_completed(&self.db, oid, completed_at).await
    }

    async fn record_authorization_request_consent(
        &self,
        oid: Uuid,
        consent_state: ConsentState,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        consent::record_authorization_request_consent(&self.db, oid, consent_state, decided_at)
            .await
    }

    async fn has_user_consent(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
        requested_scope: &ScopeSet,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        consent::has_user_consent(&self.db, user_oid, client_oid, requested_scope).await
    }

    async fn user_consented_scope_names(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
    ) -> Result<Vec<String>, ClientAuthorizationRepositoryError> {
        consent::user_consented_scope_names(&self.db, user_oid, client_oid).await
    }

    async fn revoke_access_tokens_for_authorization_code(
        &self,
        authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        token_revocation::revoke_access_tokens_for_authorization_code(
            &self.db,
            authorization_code_oid,
        )
        .await
    }

    async fn revoke_if_active(
        &self,
        oid: Uuid,
        type_: ClientAuthorizationType,
        now: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        token_revocation::revoke_if_active(&self.db, oid, type_, now).await
    }

    async fn revoke_refresh_token_family(
        &self,
        refresh_oid: Uuid,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        token_revocation::revoke_refresh_token_family(&self.db, refresh_oid, client_oid, now).await
    }

    async fn revoke_access_token_for_client(
        &self,
        access_oid: Uuid,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        token_revocation::revoke_access_token_for_client(&self.db, access_oid, client_oid, now)
            .await
    }

    async fn revoke_refresh_grant_for_client(
        &self,
        refresh_oid: Uuid,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        token_revocation::revoke_refresh_grant_for_client(&self.db, refresh_oid, client_oid, now)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::backtrace::BacktraceStatus;

    use identity_application::error::ErrorDiagnostics;
    use sea_orm::DbErr;

    use super::query_failed;

    #[test]
    fn query_diagnostics_capture_a_real_stack_before_application_wrapping() {
        let error = query_failed("test.query", DbErr::Custom("bad SQL".into()));
        let diagnostics = ErrorDiagnostics::from_error(&error);
        assert_eq!(diagnostics.operation, Some("test.query"));
        assert_eq!(
            diagnostics.backtrace.unwrap().status(),
            BacktraceStatus::Captured
        );
        assert_eq!(diagnostics.cause, "Custom Error: bad SQL");
    }
}

#[cfg(test)]
mod par_tests {
    use chrono::Duration;
    use identity_domain::{
        client_authorization::PushedAuthorizationRequestData,
        openid_connect::model::authorization_request::AuthorizationRequestParams,
    };
    use sea_orm::MockDatabase;
    use serde_json::to_value;

    use super::*;

    #[tokio::test]
    async fn consumption_is_one_statement_conditioned_on_type_owner_expiry_and_unused_state() {
        let now = Utc::now();
        let params = AuthorizationRequestParams {
            client_id: Uuid::nil().to_string(),
            scope: "openid".to_owned(),
            ..Default::default()
        };
        let row = client_authorization::Model {
            id: 1,
            oid: Uuid::new_v4(),
            client_id: 7,
            r#type: ClientAuthorizationType::PushedAuthorizationRequest.to_string(),
            data: to_value(PushedAuthorizationRequestData {
                request_uri_digest: "digest".to_owned(),
                parameters: params.clone(),
            })
            .unwrap(),
            expires_at: (now + Duration::seconds(90)).into(),
            completed_at: Some(now.into()),
            revoked_at: None,
            is_expired: false,
            created_at: now.into(),
            updated_at: Some(now.into()),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![row], vec![]])
            .into_connection();
        let repo = ClientAuthorizationRepositoryImpl::new(db.clone());
        assert_eq!(
            repo.consume_pushed_authorization_request("digest", Uuid::nil(), now)
                .await
                .unwrap(),
            Some(PushedAuthorizationRequestData {
                request_uri_digest: "digest".to_owned(),
                parameters: params
            })
        );
        assert!(
            repo.consume_pushed_authorization_request("digest", Uuid::nil(), now)
                .await
                .unwrap()
                .is_none()
        );
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 2);
        let sql = format!("{:?}", log[0]);
        for predicate in [
            "UPDATE",
            "client_authorization",
            "pushed_authorization_request",
            "request_uri_digest",
            "SELECT",
            "expires_at",
            "completed_at",
            "IS NULL",
            "revoked_at",
            "is_expired",
            "RETURNING",
        ] {
            assert!(sql.contains(predicate), "{sql}");
        }
    }
}
