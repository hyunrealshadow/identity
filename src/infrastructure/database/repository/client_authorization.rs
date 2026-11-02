use crate::database::{
    authority_snapshot::user_authority_fingerprint,
    entity::{
        client::Entity as ClientEntity, client_authorization,
        client_authorization::Entity as ClientAuthorizationEntity,
    },
    repository::{
        client_authorization_query as query,
        shared::{lock_resource_rows, lock_session, lock_user_credentials},
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::error::ErrorContext;
use identity_domain::{
    auth::SessionOid,
    client::model::ClientOid,
    client_authorization::{
        AccessTokenPrincipal, ClientAuthorization, ClientAuthorizationData,
        ClientAuthorizationRepository, ClientAuthorizationRepositoryError, ClientAuthorizationType,
        ConsentState, PushedAuthorizationRequestData, SelectionSource,
    },
    openid_connect::ScopeSet,
    user::UserOid,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr,
    EntityTrait, FromQueryResult, QueryFilter, Set, Statement, TransactionTrait,
};
use serde_json::from_value;
use std::error::Error;
use uuid::Uuid;

mod consent;
mod mapping;
mod request_interaction;
mod token_revocation;

/// Internal reasons why the authoritative live state rejects issuance. These
/// are mapped by callers to stable protocol/`AppError` codes and never expose
/// SQL or subject details.
#[derive(Debug, thiserror::Error)]
enum LiveAuthorizationState {
    #[error("client management policy is unavailable or disabled")]
    ClientInactive,
    #[error("user is disabled or locked")]
    UserInactive,
    #[error("session is not active or does not belong to the subject")]
    SessionInactive,
    #[error("the parent authorization was revoked or expired")]
    ParentInactive,
}

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

/// Extract the human subject that must be checked for live state. Machine
/// access tokens have an explicit client principal and carry no user OID; this
/// function never invents one.
fn subject_user_oid(
    data: &ClientAuthorizationData,
) -> Result<Option<Uuid>, ClientAuthorizationRepositoryError> {
    let raw = match data {
        ClientAuthorizationData::AuthorizationCode(data) => Some(data.user_oid.as_str()),
        ClientAuthorizationData::AccessToken(data) => {
            if data.principal == AccessTokenPrincipal::Client {
                None
            } else {
                data.user_oid.as_deref()
            }
        }
        ClientAuthorizationData::RefreshToken(data) => Some(data.user_oid.as_str()),
        ClientAuthorizationData::DeviceAuthorization(data) => Some(data.user_oid.as_str()),
        _ => None,
    };
    raw.map(|value| {
        Uuid::parse_str(value).map_err(|error| query_failed("client_authorization.create", error))
    })
    .transpose()
}

/// The actual API-resource targets serialized with an artifact. These are the
/// same URIs used for the JWT audience/scope decision at issuance; the list is
/// never derived from a client ID or an optimistic-lock version. Queued
/// authorization requests carry the list under their nested request document.
fn target_resource_uris(data: &ClientAuthorizationData) -> Vec<String> {
    match data {
        ClientAuthorizationData::AuthorizationCode(data) => data.resources.clone(),
        ClientAuthorizationData::AccessToken(data) => data.resources.clone(),
        ClientAuthorizationData::RefreshToken(data) => data.resources.clone(),
        ClientAuthorizationData::DeviceAuthorizationRequest(data) => data.resources.clone(),
        ClientAuthorizationData::DeviceAuthorization(data) => data.resources.clone(),
        ClientAuthorizationData::PushedAuthorizationRequest(data) => {
            data.parameters.resources.clone()
        }
        ClientAuthorizationData::AuthorizationRequest(data) => data.request.resources.clone(),
        ClientAuthorizationData::RegistrationAccessToken(_) => Vec::new(),
    }
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
        let user_oid = subject_user_oid(&data)?;
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
        super::authorization_lifecycle::lock_authorization_issuance(&transaction)
            .await
            .map_err(query_error("client_authorization.create"))?;
        // Resource target rows follow the shared lifecycle lock, in URI order and
        // before the credential/user/session/client/parent sequence below.
        // Semantic resource writers take a conflicting row UPDATE before
        // permanently withdrawing artifacts, so a withdrawal cannot slip
        // between target validation and this INSERT.
        let target_resources = target_resource_uris(&data);
        lock_resource_rows(&transaction, &target_resources)
            .await
            .map_err(query_error("client_authorization.create"))?;
        // Lock order matches password/session transitions: the account
        // credential lock first, then session locks, then the client row and
        // its protocol registration before persistence. Machine tokens carry no user
        // subject and are never mapped to a fake user.
        if let Some(user_oid) = user_oid {
            lock_user_credentials(&transaction, UserOid(user_oid))
                .await
                .map_err(query_error("client_authorization.create"))?;
            let user_state = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT u.enabled AND NOT u.locked AS active
                       FROM "user" u WHERE u.oid=$1 FOR SHARE OF u"#,
                    [user_oid.into()],
                ))
                .await
                .map_err(query_error("client_authorization.create"))?;
            let user_state = user_state.ok_or_else(|| {
                query_failed(
                    "client_authorization.create",
                    LiveAuthorizationState::UserInactive,
                )
            })?;
            let active = user_state
                .try_get::<bool>("", "active")
                .map_err(query_error("client_authorization.create"))?;
            if !active {
                return Err(query_failed(
                    "client_authorization.create",
                    LiveAuthorizationState::UserInactive,
                ));
            }
        }
        if let Some(session_oid) = session_oid {
            lock_session(&transaction, session_oid)
                .await
                .map_err(query_error("client_authorization.create"))?;
            let session_state = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"
SELECT (
    s.status = 'active'
    AND s.revoked_at IS NULL
    AND (s.expires_at IS NULL OR s.expires_at > now())
    AND ($1::uuid IS NULL OR u.oid = $1::uuid)
) AS active
FROM session s
JOIN "user" u ON u.id = s.user_id
WHERE s.oid = $2
FOR SHARE OF s
"#,
                    [user_oid.into(), Uuid::from(session_oid).into()],
                ))
                .await
                .map_err(query_error("client_authorization.create"))?;
            let active = session_state
                .and_then(|row| row.try_get::<bool>("", "active").ok())
                .unwrap_or(false);
            if !active {
                return Err(query_failed(
                    "client_authorization.create",
                    LiveAuthorizationState::SessionInactive,
                ));
            }
        }
        if let Some(parent_oid) = family_refresh_oid {
            lock_refresh_family(&transaction, parent_oid, client_oid, true).await?;
        }
        // Hold the client share lock through INSERT so registration changes
        // or deletion cannot interleave between validation and persistence.
        let client_row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT id FROM client WHERE oid = $1 FOR SHARE",
                [client_oid.into()],
            ))
            .await
            .map_err(query_error("client_authorization.create"))?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.create",
                    DbErr::RecordNotFound(format!("client {client_oid} not found")),
                )
            })?;
        let client_id = client_row
            .try_get::<i64>("", "id")
            .map_err(query_error("client_authorization.create"))?;
        // Both the client and its protocol registration must still exist.
        // Derive semantic authority under those share locks, held through INSERT.
        let (client_configured, client_fingerprint) =
            crate::database::repository::client_authority::lock_live_client_boundary(
                &transaction,
                client_id,
            )
            .await
            .map_err(query_error("client_authorization.create"))?;
        if !client_configured {
            return Err(query_failed(
                "client_authorization.create",
                LiveAuthorizationState::ClientInactive,
            ));
        }

        // Derive the subject authority fingerprint only after the inactive
        // user, session and client guards above, from this same transaction.
        // Machine grants have no user subject and are never assigned one.
        let authority_fingerprint = match user_oid {
            Some(oid) => Some(
                user_authority_fingerprint(&transaction, UserOid(oid))
                    .await
                    .map_err(query_error("client_authorization.create"))?,
            ),
            None => None,
        };

        // Code redemption/refresh may have passed application validation before
        // a concurrent disable/re-enable cycle. Re-read their original records
        // while holding the client lock; never revive that withdrawn grant.
        let parent = match &data {
            ClientAuthorizationData::AccessToken(value) => value
                .refresh_token_oid
                .as_deref()
                .map(|id| (id, "refresh_token"))
                .or_else(|| {
                    value
                        .authorization_code_oid
                        .as_deref()
                        .map(|id| (id, "authorization_code"))
                })
                .or_else(|| {
                    value
                        .device_authorization_oid
                        .as_deref()
                        .map(|id| (id, "device_authorization"))
                }),
            ClientAuthorizationData::RefreshToken(value) => value
                .rotated_from
                .as_deref()
                .map(|id| (id, "refresh_token"))
                .or_else(|| {
                    value
                        .authorization_code_oid
                        .as_deref()
                        .map(|id| (id, "authorization_code"))
                })
                .or_else(|| {
                    value
                        .device_authorization_oid
                        .as_deref()
                        .map(|id| (id, "device_authorization"))
                }),
            _ => None,
        };
        if let Some((parent, parent_type)) = parent {
            let parent =
                Uuid::parse_str(parent).map_err(query_error("client_authorization.create"))?;
            let live = transaction.query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT data FROM client_authorization WHERE oid=$1 AND client_id=$2 AND type=$3 AND (type IN ('authorization_code','refresh_token') OR revoked_at IS NULL) AND COALESCE(data->>'_authority_withdrawn', 'false') <> 'true' AND NOT is_expired AND expires_at>now() FOR SHARE",
                [parent.into(), client_id.into(), parent_type.into()],
            )).await.map_err(query_error("client_authorization.create"))?;
            let live = live.ok_or_else(|| {
                query_failed(
                    "client_authorization.create",
                    LiveAuthorizationState::ParentInactive,
                )
            })?;
            let original = live
                .try_get::<serde_json::Value>("", "data")
                .map_err(query_error("client_authorization.create"))?;
            // Single-use codes/RTs are marked revoked when consumed. Their
            // derived subject and client-authority fingerprints distinguish
            // that consumption from a later account/client change, including
            // disable/re-enable cycles. A missing or malformed fingerprint is
            // corruption and must fail closed; there is no constant baseline
            // fallback or record-version alias.
            let original_client_fingerprint = original
                .get("_issuance_client_fingerprint")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            let original_authority_fingerprint = original
                .get("_issuance_authority_fingerprint")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            let version_matches = original_client_fingerprint == Some(client_fingerprint.as_uuid())
                && match authority_fingerprint {
                    Some(fingerprint) => {
                        original_authority_fingerprint == Some(fingerprint.as_uuid())
                    }
                    None => original_authority_fingerprint.is_none(),
                };
            if !version_matches {
                return Err(query_failed(
                    "client_authorization.create",
                    LiveAuthorizationState::ParentInactive,
                ));
            }
        }

        let now = Utc::now();
        let mut data = serialize_data(&data)?;
        if let Some(object) = data.as_object_mut() {
            object.insert(
                "_issuance_client_fingerprint".into(),
                client_fingerprint.as_uuid().to_string().into(),
            );
            if let Some(fingerprint) = authority_fingerprint {
                object.insert(
                    "_issuance_authority_fingerprint".into(),
                    fingerprint.as_uuid().to_string().into(),
                );
            }
        }
        let model = client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(Uuid::new_v4()),
            client_id: Set(client_id),
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
        resources: &[String],
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        consent::has_user_consent(&self.db, user_oid, client_oid, requested_scope, resources).await
    }

    async fn user_consented_scope_names(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
        resources: &[String],
    ) -> Result<Vec<String>, ClientAuthorizationRepositoryError> {
        consent::user_consented_scope_names(&self.db, user_oid, client_oid, resources).await
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
    use identity_domain::client_authorization::{
        AccessTokenData, AccessTokenPrincipal, AuthorizationCodeData, ClientAuthorizationData,
    };
    use sea_orm::DbErr;
    use uuid::Uuid;

    use super::{query_failed, subject_user_oid};

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

    #[test]
    fn machine_tokens_never_select_a_fake_user_subject() {
        let subject = Uuid::new_v4();
        let machine = ClientAuthorizationData::AccessToken(AccessTokenData {
            scope: "management.audit.read".to_owned(),
            resources: Vec::new(),
            user_oid: Some(subject.to_string()),
            principal: AccessTokenPrincipal::Client,
            session_oid: None,
            protected_session_id: None,
            authorization_code_oid: None,
            refresh_token_oid: None,
            device_authorization_oid: None,
            client_authentication_mode: None,
            management: None,
        });
        assert_eq!(subject_user_oid(&machine).unwrap(), None);

        let human = ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
            scope: "openid".to_owned(),
            resources: Vec::new(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            user_oid: subject.to_string(),
            session_oid: identity_domain::auth::SessionOid(Uuid::new_v4()),
            protected_session_id: None,
            acr: None,
            amr: Vec::new(),
            redirect_uri: "https://example.test/cb".to_owned(),
            redirect_uri_was_supplied: true,
            auth_time: None,
            claims: None,
            management: None,
        });
        assert_eq!(subject_user_oid(&human).unwrap(), Some(subject));
    }
}
