use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_application::error::ErrorContext;
use identity_domain::auth::SessionStatus;
use identity_domain::client_authorization::PushedAuthorizationRequestData;
use sea_orm::DbErr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, EntityTrait, FromQueryResult, QueryFilter, QuerySelect, Set,
    TransactionTrait,
    sea_query::{Expr, OnConflict, SimpleExpr},
};
use serde_json::Value;
use std::error::Error;
use uuid::Uuid;

use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity, scope, scope::Entity as ScopeEntity,
    session, session::Entity as SessionEntity, user, user::Entity as UserEntity,
    user_client_consent, user_client_consent::Entity as UserClientConsentEntity,
};
use crate::database::query::{advisory_transaction_lock, json_text};
use crate::database::repository::{client_authorization_query as query, shared::lock_session};
use identity_domain::{
    auth::SessionOid,
    client::model::ClientOid,
    client_authorization::{
        AccessTokenData, AuthorizationCodeData, ClientAuthorization, ClientAuthorizationData,
        ClientAuthorizationRepository, ClientAuthorizationRepositoryError, ClientAuthorizationType,
        ConsentState, DeviceAuthorizationData, DeviceAuthorizationRequestData, RefreshTokenData,
        RegistrationAccessTokenData, SelectionSource, StoredAuthorizationRequest,
    },
    openid_connect::{AuthorizationRequestData, ScopeSet},
};
use sea_orm::sea_query::{ExprTrait, Func};

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

fn parse_stored_authorization_request(
    data: Value,
) -> Result<StoredAuthorizationRequest, ClientAuthorizationRepositoryError> {
    serde_json::from_value::<StoredAuthorizationRequest>(data.clone())
        .or_else(|_| {
            serde_json::from_value::<AuthorizationRequestData>(data).map(|request| {
                StoredAuthorizationRequest {
                    request,
                    interaction: Default::default(),
                }
            })
        })
        .map_err(|_| {
            query_failed(
                "client_authorization.parse_stored_authorization_request",
                DbErr::Type("invalid authorization_request payload".into()),
            )
        })
}

pub(super) fn serialize_data(
    data: &ClientAuthorizationData,
) -> Result<Value, ClientAuthorizationRepositoryError> {
    match data {
        ClientAuthorizationData::PushedAuthorizationRequest(value) => serde_json::to_value(value),
        ClientAuthorizationData::AuthorizationRequest(value) => serde_json::to_value(value),
        ClientAuthorizationData::AuthorizationCode(value) => serde_json::to_value(value),
        ClientAuthorizationData::AccessToken(value) => serde_json::to_value(value),
        ClientAuthorizationData::RefreshToken(value) => serde_json::to_value(value),
        ClientAuthorizationData::RegistrationAccessToken(value) => serde_json::to_value(value),
        ClientAuthorizationData::DeviceAuthorizationRequest(value) => serde_json::to_value(value),
        ClientAuthorizationData::DeviceAuthorization(value) => serde_json::to_value(value),
    }
    .map_err(query_error("client_authorization.serialize_data"))
}

fn scope_ids_cover(mut granted: Vec<i64>, mut requested: Vec<i64>) -> bool {
    granted.sort_unstable();
    granted.dedup();
    requested.sort_unstable();
    requested.dedup();

    requested
        .iter()
        .all(|scope_id| granted.binary_search(scope_id).is_ok())
}

fn parse_data(
    type_: &ClientAuthorizationType,
    data: Value,
) -> Result<ClientAuthorizationData, ClientAuthorizationRepositoryError> {
    match type_ {
        ClientAuthorizationType::PushedAuthorizationRequest => {
            serde_json::from_value::<PushedAuthorizationRequestData>(data)
                .map(ClientAuthorizationData::PushedAuthorizationRequest)
        }
        ClientAuthorizationType::AuthorizationRequest => {
            return parse_stored_authorization_request(data)
                .map(ClientAuthorizationData::AuthorizationRequest);
        }
        ClientAuthorizationType::AuthorizationCode => {
            serde_json::from_value::<AuthorizationCodeData>(data)
                .map(ClientAuthorizationData::AuthorizationCode)
        }
        ClientAuthorizationType::AccessToken => serde_json::from_value::<AccessTokenData>(data)
            .map(ClientAuthorizationData::AccessToken),
        ClientAuthorizationType::RefreshToken => serde_json::from_value::<RefreshTokenData>(data)
            .map(ClientAuthorizationData::RefreshToken),
        ClientAuthorizationType::RegistrationAccessToken => {
            serde_json::from_value::<RegistrationAccessTokenData>(data)
                .map(ClientAuthorizationData::RegistrationAccessToken)
        }
        ClientAuthorizationType::DeviceAuthorizationRequest => {
            serde_json::from_value::<DeviceAuthorizationRequestData>(data)
                .map(ClientAuthorizationData::DeviceAuthorizationRequest)
        }
        ClientAuthorizationType::DeviceAuthorization => {
            serde_json::from_value::<DeviceAuthorizationData>(data)
                .map(ClientAuthorizationData::DeviceAuthorization)
        }
    }
    .map_err(query_error("client_authorization.parse_data"))
}

fn selection_update_condition(
    model: &client_authorization::Model,
    now: DateTime<Utc>,
) -> Condition {
    let mut condition = Condition::all()
        .add(client_authorization::Column::Oid.eq(model.oid))
        .add(
            client_authorization::Column::Type
                .eq(ClientAuthorizationType::AuthorizationRequest.to_string()),
        )
        .add(client_authorization::Column::CompletedAt.is_null())
        .add(client_authorization::Column::RevokedAt.is_null())
        .add(client_authorization::Column::ExpiresAt.gt(now));

    condition = if let Some(updated_at) = model.updated_at {
        condition.add(client_authorization::Column::UpdatedAt.eq(updated_at))
    } else {
        condition.add(client_authorization::Column::UpdatedAt.is_null())
    };

    condition
}

pub(super) fn to_domain(
    model: client_authorization::Model,
    client_oid: ClientOid,
) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
    let type_ = model
        .r#type
        .parse::<ClientAuthorizationType>()
        .map_err(|_| {
            query_failed(
                "client_authorization.to_domain",
                DbErr::Type("invalid client_authorization.type".into()),
            )
        })?;
    let data = parse_data(&type_, model.data)?;

    Ok(ClientAuthorization {
        oid: model.oid,
        client_oid,
        type_,
        data,
        expires_at: model.expires_at.with_timezone(&Utc),
        completed_at: model.completed_at.map(|value| value.with_timezone(&Utc)),
        revoked_at: model.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|value| value.with_timezone(&Utc)),
    })
}

pub struct ClientAuthorizationRepositoryImpl {
    db: DatabaseConnection,
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

async fn lock_refresh_family(
    transaction: &DatabaseTransaction,
    refresh_oid: Uuid,
    client_oid: ClientOid,
    reject_compromised: bool,
) -> Result<Uuid, ClientAuthorizationRepositoryError> {
    let root = transaction
        .query_one(&query::refresh_root(refresh_oid, client_oid.into()))
        .await
        .map_err(query_error("client_authorization.lock_refresh_family"))?
        .ok_or_else(|| {
            query_failed(
                "client_authorization.lock_refresh_family",
                DbErr::RecordNotFound("refresh token family not found".into()),
            )
        })?;
    let root_oid: Uuid = root
        .try_get("", "root_oid")
        .map_err(query_error("client_authorization.lock_refresh_family"))?;
    transaction
        .query_one(&advisory_transaction_lock(
            Func::cust("hashtextextended")
                .args([Expr::value(root_oid.to_string()), Expr::value(0_i64)]),
        ))
        .await
        .map_err(query_error("client_authorization.lock_refresh_family"))?;
    if reject_compromised {
        let row = transaction
            .query_one(&query::refresh_compromised(root_oid))
            .await
            .map_err(query_error("client_authorization.lock_refresh_family"))?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.lock_refresh_family",
                    DbErr::RecordNotFound("refresh token family root not found".into()),
                )
            })?;
        let compromised: bool = row
            .try_get("", "compromised")
            .map_err(query_error("client_authorization.lock_refresh_family"))?;
        if compromised {
            return Err(query_failed(
                "client_authorization.lock_refresh_family",
                DbErr::RecordNotFound("refresh token family was revoked".into()),
            ));
        }
    }
    Ok(root_oid)
}

impl ClientAuthorizationRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
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
        .map_err(|error| {
            query_failed(
                "client_authorization.consume_pushed_authorization_request",
                error,
            )
        })?;
        row.map(|row| {
            serde_json::from_value::<PushedAuthorizationRequestData>(row.data).map_err(|error| {
                query_failed(
                    "client_authorization.consume_pushed_authorization_request",
                    error,
                )
            })
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
            .map_err(|e| query_failed("client_authorization.create", e))?
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
        .map_err(|e| query_failed("client_authorization.create", e))?;
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
            .map_err(|e| query_failed("client_authorization.find_by_oid", e))?
        else {
            return Ok(None);
        };

        Ok(Some(to_domain(request_model, client_model.oid)?))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_authorization_request_selection"))]
    async fn update_authorization_request_selection(
        &self,
        oid: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let Some(model) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(|e| {
                query_failed(
                    "client_authorization.update_authorization_request_selection",
                    e,
                )
            })?
        else {
            return Ok(false);
        };

        if model.r#type != ClientAuthorizationType::AuthorizationRequest.to_string()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= Utc::now()
        {
            return Ok(false);
        }

        let mut stored = parse_stored_authorization_request(model.data.clone())?;
        if !source.can_replace(stored.interaction.selection_source) {
            return Ok(false);
        }

        stored.interaction.selected_session_oid = Some(session_oid);
        stored.interaction.selected_protected_session_id = protected_session_id;
        stored.interaction.selected_user_oid = Some(user_oid.to_string());
        stored.interaction.selection_source = Some(source);

        let now = Utc::now();
        let stored_data = serde_json::to_value(stored).map_err(|e| {
            query_failed(
                "client_authorization.update_authorization_request_selection",
                e,
            )
        })?;
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(stored_data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(selection_update_condition(&model, now))
            .exec(&self.db)
            .await
            .map_err(|e| {
                query_failed(
                    "client_authorization.update_authorization_request_selection",
                    e,
                )
            })?;

        Ok(result.rows_affected == 1)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "record_authorization_request_consent"))]
    async fn record_authorization_request_consent(
        &self,
        oid: Uuid,
        consent_state: ConsentState,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let Some(model) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(|e| {
                query_failed(
                    "client_authorization.record_authorization_request_consent",
                    e,
                )
            })?
        else {
            return Ok(false);
        };

        if model.r#type != ClientAuthorizationType::AuthorizationRequest.to_string()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= Utc::now()
        {
            return Ok(false);
        }

        let mut stored = parse_stored_authorization_request(model.data.clone())?;
        if stored.interaction.consent_state != ConsentState::Pending {
            return Ok(false);
        }

        let grant = if consent_state == ConsentState::Approved {
            let user_oid = stored
                .interaction
                .selected_user_oid
                .as_deref()
                .ok_or_else(|| {
                    query_failed(
                        "client_authorization.record_authorization_request_consent",
                        DbErr::Type("approved consent has no selected user".into()),
                    )
                })?
                .parse::<Uuid>()
                .map_err(|error| {
                    query_failed(
                        "client_authorization.record_authorization_request_consent",
                        error,
                    )
                })?;
            let scope = ScopeSet::parse(&stored.request.scope).map_err(|error| {
                query_failed(
                    "client_authorization.record_authorization_request_consent",
                    error,
                )
            })?;
            Some((user_oid, scope))
        } else {
            None
        };

        stored.interaction.consent_state = consent_state;
        stored.interaction.consent_decided_at = Some(decided_at.to_rfc3339());

        let now = Utc::now();
        let stored_data = serde_json::to_value(stored).map_err(|e| {
            query_failed(
                "client_authorization.record_authorization_request_consent",
                e,
            )
        })?;
        let transaction = self.db.begin().await.map_err(|error| {
            query_failed(
                "client_authorization.record_authorization_request_consent",
                error,
            )
        })?;
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(stored_data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(selection_update_condition(&model, now))
            .exec(&transaction)
            .await
            .map_err(|e| {
                query_failed(
                    "client_authorization.record_authorization_request_consent",
                    e,
                )
            })?;

        if result.rows_affected != 1 {
            return Ok(false);
        }

        if let Some((user_oid, requested_scope)) = grant {
            let user_id = UserEntity::find()
                .select_only()
                .column(user::Column::Id)
                .filter(user::Column::Oid.eq(user_oid))
                .into_tuple::<i64>()
                .one(&transaction)
                .await
                .map_err(|error| {
                    query_failed(
                        "client_authorization.record_authorization_request_consent",
                        error,
                    )
                })?
                .ok_or_else(|| {
                    query_failed(
                        "client_authorization.record_authorization_request_consent",
                        DbErr::RecordNotFound(format!("user {user_oid} not found")),
                    )
                })?;
            let requested_scope_names = requested_scope.names();
            let mut scope_ids = ScopeEntity::find()
                .select_only()
                .column(scope::Column::Id)
                .filter(scope::Column::Protocol.eq("openid_connect"))
                .filter(scope::Column::Name.is_in(requested_scope_names.iter().copied()))
                .into_tuple::<i64>()
                .all(&transaction)
                .await
                .map_err(|error| {
                    query_failed(
                        "client_authorization.record_authorization_request_consent",
                        error,
                    )
                })?;
            scope_ids.sort_unstable();
            scope_ids.dedup();
            if scope_ids.len() != requested_scope_names.len() {
                return Err(query_failed(
                    "client_authorization.record_authorization_request_consent",
                    DbErr::RecordNotFound("one or more consent scopes were not found".to_owned()),
                ));
            }
            let grants = scope_ids
                .into_iter()
                .map(|scope_id| user_client_consent::ActiveModel {
                    scope_id: Set(scope_id),
                    user_id: Set(user_id),
                    client_id: Set(model.client_id),
                    approved_at: Set(decided_at.into()),
                    ..Default::default()
                });
            UserClientConsentEntity::insert_many(grants)
                .on_conflict(
                    OnConflict::columns([
                        user_client_consent::Column::UserId,
                        user_client_consent::Column::ClientId,
                        user_client_consent::Column::ScopeId,
                    ])
                    .update_column(user_client_consent::Column::ApprovedAt)
                    .to_owned(),
                )
                .exec(&transaction)
                .await
                .map_err(|error| {
                    query_failed(
                        "client_authorization.record_authorization_request_consent",
                        error,
                    )
                })?;
        }

        transaction.commit().await.map_err(|error| {
            query_failed(
                "client_authorization.record_authorization_request_consent",
                error,
            )
        })?;
        Ok(true)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "has_user_consent"))]
    async fn has_user_consent(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
        requested_scope: &ScopeSet,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let Some(user) = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(query_error("client_authorization.has_user_consent"))?
        else {
            return Ok(false);
        };
        let Some(client) = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&self.db)
            .await
            .map_err(query_error("client_authorization.has_user_consent"))?
        else {
            return Ok(false);
        };
        let requested_scope_names = requested_scope.names();
        let mut requested_scope_ids = ScopeEntity::find()
            .select_only()
            .column(scope::Column::Id)
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .filter(scope::Column::Name.is_in(requested_scope_names.iter().copied()))
            .into_tuple::<i64>()
            .all(&self.db)
            .await
            .map_err(query_error("client_authorization.has_user_consent"))?;
        requested_scope_ids.sort_unstable();
        requested_scope_ids.dedup();
        if requested_scope_ids.len() != requested_scope_names.len() {
            return Ok(false);
        }

        let granted_scope_ids = UserClientConsentEntity::find()
            .select_only()
            .column(user_client_consent::Column::ScopeId)
            .filter(user_client_consent::Column::UserId.eq(user.id))
            .filter(user_client_consent::Column::ClientId.eq(client.id))
            .into_tuple::<i64>()
            .all(&self.db)
            .await
            .map_err(query_error("client_authorization.has_user_consent"))?;
        Ok(scope_ids_cover(granted_scope_ids, requested_scope_ids))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_consented_scope_names"))]
    async fn user_consented_scope_names(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
    ) -> Result<Vec<String>, ClientAuthorizationRepositoryError> {
        UserClientConsentEntity::find()
            .select_only()
            .column(scope::Column::Name)
            .inner_join(UserEntity)
            .inner_join(ClientEntity)
            .inner_join(ScopeEntity)
            .filter(user::Column::Oid.eq(user_oid))
            .filter(client::Column::Oid.eq(client_oid))
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .into_tuple::<String>()
            .all(&self.db)
            .await
            .map_err(query_error(
                "client_authorization.user_consented_scope_names",
            ))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "mark_authorization_request_completed"))]
    async fn mark_authorization_request_completed(
        &self,
        oid: Uuid,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let now = Utc::now();
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::CompletedAt,
                SimpleExpr::Value(Some(completed_at).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::Oid.eq(oid))
                    .add(
                        client_authorization::Column::Type
                            .eq(ClientAuthorizationType::AuthorizationRequest.to_string()),
                    )
                    .add(client_authorization::Column::CompletedAt.is_null())
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(client_authorization::Column::ExpiresAt.gt(now)),
            )
            .exec(&self.db)
            .await
            .map_err(|e| {
                query_failed(
                    "client_authorization.mark_authorization_request_completed",
                    e,
                )
            })?;

        Ok(result.rows_affected == 1)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_access_tokens_for_authorization_code"))]
    async fn revoke_access_tokens_for_authorization_code(
        &self,
        authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        let now = Utc::now();
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(now.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(now.into()),
            )
            .filter(
                Condition::all()
                    .add(
                        client_authorization::Column::Type
                            .eq(ClientAuthorizationType::AccessToken.to_string()),
                    )
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(
                        json_text(
                            (
                                client_authorization::Entity,
                                client_authorization::Column::Data,
                            ),
                            "authorization_code_oid",
                        )
                        .eq(authorization_code_oid.to_string()),
                    ),
            )
            .exec(&self.db)
            .await
            .map_err(|e| {
                query_failed(
                    "client_authorization.revoke_access_tokens_for_authorization_code",
                    e,
                )
            })?;

        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_if_active"))]
    async fn revoke_if_active(
        &self,
        oid: Uuid,
        type_: ClientAuthorizationType,
        now: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::Oid.eq(oid))
                    .add(client_authorization::Column::Type.eq(type_.to_string()))
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(client_authorization::Column::ExpiresAt.gt(now)),
            )
            .exec(&self.db)
            .await
            .map_err(|e| query_failed("client_authorization.revoke_if_active", e))?;

        Ok(result.rows_affected == 1)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_refresh_token_family"))]
    async fn revoke_refresh_token_family(
        &self,
        refresh_oid: Uuid,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(|error| {
            query_failed("client_authorization.revoke_refresh_token_family", error)
        })?;
        let root_oid = lock_refresh_family(&transaction, refresh_oid, client_oid, false).await?;
        let root = transaction
            .query_one(&query::authorization_data(root_oid))
            .await
            .map_err(|error| {
                query_failed("client_authorization.revoke_refresh_token_family", error)
            })?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.revoke_refresh_token_family",
                    DbErr::RecordNotFound("refresh token family root not found".into()),
                )
            })?;
        let data: Value = root.try_get("", "data").map_err(|error| {
            query_failed("client_authorization.revoke_refresh_token_family", error)
        })?;
        let authorization_code_oid = data["authorization_code_oid"].as_str().unwrap_or("");
        let device_authorization_oid = data["device_authorization_oid"].as_str().unwrap_or("");

        transaction
            .execute(&query::mark_refresh_flag(root_oid, "replay_detected", now))
            .await
            .map_err(|error| {
                query_failed("client_authorization.revoke_refresh_token_family", error)
            })?;
        transaction
            .execute(&query::revoke_refresh_family(
                root_oid,
                client_oid.into(),
                authorization_code_oid,
                device_authorization_oid,
                now,
            ))
            .await
            .map_err(|error| {
                query_failed("client_authorization.revoke_refresh_token_family", error)
            })?;
        if !device_authorization_oid.is_empty() {
            transaction
                .execute(&query::revoke_token_for_client(
                    Expr::col(client_authorization::Column::Oid)
                        .cast_as("text")
                        .eq(device_authorization_oid),
                    client_oid.into(),
                    "device_authorization",
                    now,
                ))
                .await
                .map_err(|error| {
                    query_failed("client_authorization.revoke_refresh_token_family", error)
                })?;
        }
        transaction.commit().await.map_err(|error| {
            query_failed("client_authorization.revoke_refresh_token_family", error)
        })?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_access_token_for_client"))]
    async fn revoke_access_token_for_client(
        &self,
        access_oid: Uuid,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        self.db
            .execute(&query::revoke_token_for_client(
                Expr::col(client_authorization::Column::Oid).eq(access_oid),
                client_oid.into(),
                "access_token",
                now,
            ))
            .await
            .map_err(|error| {
                query_failed("client_authorization.revoke_access_token_for_client", error)
            })?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_refresh_grant_for_client"))]
    async fn revoke_refresh_grant_for_client(
        &self,
        refresh_oid: Uuid,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(|error| {
            query_failed(
                "client_authorization.revoke_refresh_grant_for_client",
                error,
            )
        })?;
        let root_oid = lock_refresh_family(&transaction, refresh_oid, client_oid, false).await?;
        let root = transaction
            .query_one(&query::authorization_data(root_oid))
            .await
            .map_err(|error| {
                query_failed(
                    "client_authorization.revoke_refresh_grant_for_client",
                    error,
                )
            })?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.revoke_refresh_grant_for_client",
                    DbErr::RecordNotFound("refresh grant root not found".into()),
                )
            })?;
        let data: Value = root.try_get("", "data").map_err(|error| {
            query_failed(
                "client_authorization.revoke_refresh_grant_for_client",
                error,
            )
        })?;
        let authorization_code_oid = data["authorization_code_oid"].as_str().unwrap_or("");
        let device_authorization_oid = data["device_authorization_oid"].as_str().unwrap_or("");

        transaction
            .execute(&query::mark_refresh_flag(root_oid, "grant_revoked", now))
            .await
            .map_err(|error| {
                query_failed(
                    "client_authorization.revoke_refresh_grant_for_client",
                    error,
                )
            })?;
        transaction
            .execute(&query::revoke_refresh_family(
                root_oid,
                client_oid.into(),
                authorization_code_oid,
                device_authorization_oid,
                now,
            ))
            .await
            .map_err(|error| {
                query_failed(
                    "client_authorization.revoke_refresh_grant_for_client",
                    error,
                )
            })?;
        if !device_authorization_oid.is_empty() {
            transaction
                .execute(&query::revoke_token_for_client(
                    Expr::col(client_authorization::Column::Oid)
                        .cast_as("text")
                        .eq(device_authorization_oid),
                    client_oid.into(),
                    "device_authorization",
                    now,
                ))
                .await
                .map_err(|error| {
                    query_failed(
                        "client_authorization.revoke_refresh_grant_for_client",
                        error,
                    )
                })?;
        }
        transaction.commit().await.map_err(|error| {
            query_failed(
                "client_authorization.revoke_refresh_grant_for_client",
                error,
            )
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod selection_tests {
    use identity_domain::client_authorization::ClientAuthorizationRepository;
    use sea_orm::DatabaseBackend;
    use sea_orm::MockDatabase;
    use sea_orm::Value;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    use std::backtrace::BacktraceStatus;

    use super::ClientAuthorizationRepositoryImpl;
    use super::query_failed;
    use identity_application::error::ErrorDiagnostics;
    use sea_orm::DbErr;

    use super::scope_ids_cover;
    use identity_domain::client_authorization::SelectionSource;

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
    fn reauthentication_cannot_be_replaced_by_another_selection_flow() {
        assert!(
            !SelectionSource::AccountPicker.can_replace(Some(SelectionSource::Reauthentication))
        );
        assert!(!SelectionSource::FreshLogin.can_replace(Some(SelectionSource::Reauthentication)));
        assert!(
            SelectionSource::Reauthentication.can_replace(Some(SelectionSource::Reauthentication))
        );
    }

    #[test]
    fn consent_scope_comparison_sorts_deduplicates_and_accepts_subsets() {
        assert!(scope_ids_cover(vec![3, 1, 2, 2], vec![2, 1, 1]));
        assert!(!scope_ids_cover(vec![3, 1, 1], vec![1, 2]));
    }

    #[tokio::test]
    async fn remembered_scope_lookup_is_scoped_to_account_client_and_protocol() {
        let user_oid = Uuid::new_v4();
        let client_oid = Uuid::new_v4();
        let rows = vec![BTreeMap::from([(
            "name".to_owned(),
            Value::String(Some("email".to_owned())),
        )])];
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([rows, Vec::new()])
            .into_connection();
        let repo = ClientAuthorizationRepositoryImpl::new(db.clone());
        assert_eq!(
            repo.user_consented_scope_names(user_oid, client_oid)
                .await
                .unwrap(),
            vec!["email"]
        );
        assert!(
            repo.user_consented_scope_names(Uuid::new_v4(), client_oid)
                .await
                .unwrap()
                .is_empty()
        );

        let log = format!("{:?}", db.into_transaction_log());
        assert!(log.contains(&user_oid.to_string()), "{log}");
        assert!(log.contains(&client_oid.to_string()), "{log}");
        assert!(log.contains("openid_connect"), "{log}");
        assert!(log.contains("INNER JOIN"), "{log}");
    }
}

#[cfg(test)]
mod par_tests {
    use chrono::Duration;

    use super::*;
    use identity_domain::client_authorization::PushedAuthorizationRequestData;
    use identity_domain::openid_connect::model::authorization_request::AuthorizationRequestParams;
    use sea_orm::MockDatabase;

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
            data: serde_json::to_value(PushedAuthorizationRequestData {
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
