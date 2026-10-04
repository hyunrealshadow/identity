//! Device authorization persistence (RFC 8628) on `client_authorization`.
//!
//! Requests and the relations they create share the table with the other
//! authorization artifacts and are distinguished by their `type`; the
//! concurrency guarantees come from row locks and partial unique indexes, not
//! from process-local state.

use crate::database::query::json_text;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
    sea_query::{Expr, ExprTrait, SimpleExpr},
};
use uuid::Uuid;

use super::client_authorization::{serialize_data, to_domain};
use super::shared::non_expiring_timestamp;
use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity,
};
use identity_domain::{
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationRepositoryError,
        ClientAuthorizationType, DeviceAuthorizationApproval, DeviceAuthorizationData,
        DeviceAuthorizationRepository, DeviceAuthorizationRepositoryError,
        DeviceAuthorizationRequestData, DeviceConsumeOutcome, DevicePollOutcome,
        PreparedAuthorizationRecord, SLOW_DOWN_INCREMENT_SECONDS,
    },
    openid_connect::ScopeSet,
};

/// Partial unique index guarding user codes of active device requests; the
/// name must match the index created by
/// `m20260407_060938_create_client_authorization`.
const ACTIVE_USER_CODE_INDEX: &str = "idx_client_authorization_active_user_code";

fn device_request_type() -> String {
    ClientAuthorizationType::DeviceAuthorizationRequest.to_string()
}

fn device_authorization_type() -> String {
    ClientAuthorizationType::DeviceAuthorization.to_string()
}

fn query_failed(
    error: impl std::error::Error + Send + Sync + 'static,
) -> DeviceAuthorizationRepositoryError {
    DeviceAuthorizationRepositoryError::QueryFailed(Box::new(error))
}

/// Compares a JSON field of the row against a parameter.
fn json_field_equals(field: &str, value: &str) -> SimpleExpr {
    json_text(
        (
            client_authorization::Entity,
            client_authorization::Column::Data,
        ),
        field,
    )
    .eq(value)
}

fn json_field_is_null(field: &str) -> SimpleExpr {
    json_text(
        (
            client_authorization::Entity,
            client_authorization::Column::Data,
        ),
        field,
    )
    .is_null()
}

fn parse_device_request(
    data: serde_json::Value,
) -> Result<DeviceAuthorizationRequestData, DeviceAuthorizationRepositoryError> {
    serde_json::from_value(data).map_err(query_failed)
}

/// Rebuilds the domain row or maps the storage error back to the device error.
fn to_device_domain(
    result: Result<ClientAuthorization, ClientAuthorizationRepositoryError>,
) -> Result<ClientAuthorization, DeviceAuthorizationRepositoryError> {
    result.map_err(|error| match error {
        ClientAuthorizationRepositoryError::QueryFailed(source) => {
            DeviceAuthorizationRepositoryError::QueryFailed(source)
        }
    })
}

pub struct DeviceAuthorizationRepositoryImpl {
    db: DatabaseConnection,
}

impl DeviceAuthorizationRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    fn write_data(
        data: &ClientAuthorizationData,
    ) -> Result<serde_json::Value, DeviceAuthorizationRepositoryError> {
        serialize_data(data).map_err(|error| match error {
            ClientAuthorizationRepositoryError::QueryFailed(source) => {
                DeviceAuthorizationRepositoryError::QueryFailed(source)
            }
        })
    }

    /// Locks the row for the enclosing transaction, so competing decisions,
    /// polls and redemptions serialize on the request.
    async fn lock_row<C: ConnectionTrait>(
        transaction: &C,
        oid: Uuid,
    ) -> Result<Option<client_authorization::Model>, DeviceAuthorizationRepositoryError> {
        ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(query_failed)
    }

    async fn find_by_type(
        &self,
        oid: Uuid,
        type_: String,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError> {
        let Some((model, Some(client_model))) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .filter(client_authorization::Column::Type.eq(type_))
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(query_failed)?
        else {
            return Ok(None);
        };

        to_device_domain(to_domain(model, client_model.oid)).map(Some)
    }

    async fn insert_record<C: ConnectionTrait>(
        transaction: &C,
        client_id: i64,
        record: &PreparedAuthorizationRecord,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceAuthorizationRepositoryError> {
        let type_ = record.data.authorization_type();
        let data = Self::write_data(&record.data)?;

        client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(record.oid),
            client_id: Set(client_id),
            r#type: Set(type_.to_string()),
            data: Set(data),
            expires_at: Set(record.expires_at.into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            is_expired: Set(record.expires_at <= now),
            created_at: Set(now.into()),
            updated_at: Set(None),
        }
        .insert(transaction)
        .await
        .map_err(query_failed)?;

        Ok(())
    }
}

#[async_trait]
impl DeviceAuthorizationRepository for DeviceAuthorizationRepositoryImpl {
    async fn claim_device_request(
        &self,
        request_oid: Uuid,
        login_oid: Uuid,
        session_oid: identity_domain::auth::SessionOid,
        now: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError> {
        use crate::database::entity::{login, session};
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let Some(request) = Self::lock_row(&transaction, request_oid).await? else {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        };
        if request.r#type != device_request_type()
            || request.revoked_at.is_some()
            || request.expires_at <= now
            || request.completed_at.is_some()
        {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        }
        let mut data = parse_device_request(request.data.clone())?;
        if !data.is_pending() || data.claimed_login_oid.is_some_and(|oid| oid != login_oid) {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        }
        let Some(login) = login::Entity::find()
            .filter(login::Column::Oid.eq(login_oid))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(query_failed)?
        else {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        };
        if login.client_authorization_id != request.id
            || login.client_id != request.client_id
            || login.expires_at <= now
            || !matches!(
                login.status.as_str(),
                "created" | "identifier_verified" | "authenticated"
            )
        {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        }
        let Some(session) = session::Entity::find()
            .filter(session::Column::Oid.eq(session_oid.0))
            .filter(session::Column::Status.eq("active"))
            .filter(session::Column::RevokedAt.is_null())
            .filter(session::Column::ExpiresAt.gt(now))
            .one(&transaction)
            .await
            .map_err(query_failed)?
        else {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        };
        if data.claimed_login_oid.is_some() {
            let same =
                login.session_id == Some(session.id) && login.user_id == Some(session.user_id);
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(same);
        }
        if login.status == "authenticated"
            && (login.session_id != Some(session.id) || login.user_id != Some(session.user_id))
        {
            transaction.rollback().await.map_err(query_failed)?;
            return Ok(false);
        }
        login::Entity::update_many()
            .col_expr(login::Column::SessionId, Expr::value(session.id))
            .col_expr(login::Column::UserId, Expr::value(session.user_id))
            .col_expr(login::Column::Status, Expr::value("authenticated"))
            .col_expr(login::Column::Acr, Expr::value(session.acr))
            .col_expr(login::Column::UpdatedAt, Expr::value(now))
            .filter(login::Column::Id.eq(login.id))
            .exec(&transaction)
            .await
            .map_err(query_failed)?;
        data.claimed_login_oid = Some(login_oid);
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                Expr::value(serde_json::to_value(data).map_err(query_failed)?),
            )
            .col_expr(client_authorization::Column::UpdatedAt, Expr::value(now))
            .filter(client_authorization::Column::Id.eq(request.id))
            .exec(&transaction)
            .await
            .map_err(query_failed)?;
        transaction.commit().await.map_err(query_failed)?;
        Ok(true)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "create_device_request"))]
    async fn create_device_request(
        &self,
        client_oid: ClientOid,
        data: DeviceAuthorizationRequestData,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientAuthorization, DeviceAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let client_model = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&transaction)
            .await
            .map_err(query_failed)?
            .ok_or_else(|| {
                query_failed(DbErr::RecordNotFound(format!(
                    "client {client_oid} not found"
                )))
            })?;

        let now = Utc::now();
        // Release an expired owner immediately, even if the scheduled expiry
        // job has not reached it yet. The unique index still serializes active
        // owners across instances.
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::IsExpired,
                SimpleExpr::Value(true.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(client_authorization::Column::Type.eq(device_request_type()))
            .filter(json_field_equals("user_code", &data.user_code))
            .filter(client_authorization::Column::ExpiresAt.lte(now))
            .filter(client_authorization::Column::IsExpired.eq(false))
            .filter(client_authorization::Column::CompletedAt.is_null())
            .filter(client_authorization::Column::RevokedAt.is_null())
            .exec(&transaction)
            .await
            .map_err(query_failed)?;

        let model = client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(Uuid::new_v4()),
            client_id: Set(client_model.id),
            r#type: Set(device_request_type()),
            data: Set(serde_json::to_value(&data).map_err(query_failed)?),
            expires_at: Set(expires_at.into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            is_expired: Set(expires_at <= now),
            created_at: Set(now.into()),
            updated_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(|error| {
            if error.to_string().contains(ACTIVE_USER_CODE_INDEX) {
                DeviceAuthorizationRepositoryError::UserCodeConflict
            } else {
                query_failed(error)
            }
        })?;
        transaction.commit().await.map_err(query_failed)?;

        to_device_domain(to_domain(model, client_oid))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_device_request_by_oid"))]
    async fn find_device_request_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError> {
        self.find_by_type(oid, device_request_type()).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_device_request_by_device_code_digest"))]
    async fn find_device_request_by_device_code_digest(
        &self,
        digest: &str,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError> {
        let Some((model, Some(client_model))) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Type.eq(device_request_type()))
            .filter(json_field_equals("device_code_digest", digest))
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(query_failed)?
        else {
            return Ok(None);
        };

        to_device_domain(to_domain(model, client_model.oid)).map(Some)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_active_device_request_by_user_code"))]
    async fn find_active_device_request_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError> {
        let Some((model, Some(client_model))) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Type.eq(device_request_type()))
            .filter(client_authorization::Column::CompletedAt.is_null())
            .filter(client_authorization::Column::RevokedAt.is_null())
            .filter(client_authorization::Column::IsExpired.eq(false))
            .filter(client_authorization::Column::ExpiresAt.gt(Utc::now()))
            // A claimed code is semantically consumed: only an unclaimed
            // request can still be answered with the code it advertises.
            .filter(json_field_is_null("claimed_login_oid"))
            .filter(json_field_equals("user_code", user_code))
            .order_by_desc(client_authorization::Column::CreatedAt)
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(query_failed)?
        else {
            return Ok(None);
        };

        to_device_domain(to_domain(model, client_model.oid)).map(Some)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_device_authorization_by_oid"))]
    async fn find_device_authorization_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError> {
        self.find_by_type(oid, device_authorization_type()).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "record_device_poll"))]
    async fn record_device_poll(
        &self,
        request_oid: Uuid,
        polled_at: DateTime<Utc>,
    ) -> Result<DevicePollOutcome, DeviceAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let Some(model) = Self::lock_row(&transaction, request_oid).await? else {
            return Ok(DevicePollOutcome::NotPollable);
        };
        if model.r#type != device_request_type()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= polled_at
        {
            return Ok(DevicePollOutcome::NotPollable);
        }

        let mut request = parse_device_request(model.data.clone())?;
        if !(request.is_pending() || request.is_approved()) {
            return Ok(DevicePollOutcome::NotPollable);
        }

        let effective_interval = chrono::Duration::seconds(request.effective_interval_seconds());
        let too_frequent = request
            .last_polled_at
            .is_some_and(|last_polled_at| polled_at < last_polled_at + effective_interval);

        let outcome = if too_frequent {
            request.slow_down_seconds = request
                .slow_down_seconds
                .saturating_add(SLOW_DOWN_INCREMENT_SECONDS);
            DevicePollOutcome::TooFrequent
        } else {
            request.last_polled_at = Some(polled_at);
            DevicePollOutcome::Accepted
        };

        let data = Self::write_data(&ClientAuthorizationData::DeviceAuthorizationRequest(
            request,
        ))?;
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(polled_at).into()),
            )
            .filter(client_authorization::Column::Oid.eq(request_oid))
            .exec(&transaction)
            .await
            .map_err(query_failed)?;
        transaction.commit().await.map_err(query_failed)?;

        Ok(outcome)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "approve_device_request"))]
    async fn approve_device_request(
        &self,
        request_oid: Uuid,
        approval: DeviceAuthorizationApproval,
        decided_at: DateTime<Utc>,
    ) -> Result<Option<Uuid>, DeviceAuthorizationRepositoryError> {
        let approved_scope = ScopeSet::parse(&approval.approved_scope).map_err(query_failed)?;
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let Some(model) = Self::lock_row(&transaction, request_oid).await? else {
            return Ok(None);
        };
        if model.r#type != device_request_type()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= decided_at
        {
            return Ok(None);
        }

        let mut request = parse_device_request(model.data.clone())?;
        if !request.is_pending() {
            return Ok(None);
        }
        let requested_scope = ScopeSet::parse(&request.scope).map_err(query_failed)?;
        if !requested_scope.covers(&approved_scope) {
            return Err(DeviceAuthorizationRepositoryError::ScopeNotGrantable);
        }

        let relation_oid = approval.device_authorization_oid;
        let relation = DeviceAuthorizationData {
            resources: request.resources.clone(),
            scope: approval.approved_scope.clone(),
            user_oid: approval.user_oid.clone(),
            auth_time: approval.auth_time,
            acr: approval.acr.clone(),
            amr: approval.amr.clone(),
            request_oid,
            approved_at: decided_at,
        };
        client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(relation_oid),
            client_id: Set(model.client_id),
            r#type: Set(device_authorization_type()),
            data: Set(serde_json::to_value(&relation).map_err(query_failed)?),
            expires_at: Set(non_expiring_timestamp()),
            completed_at: Set(None),
            revoked_at: Set(None),
            is_expired: Set(false),
            created_at: Set(decided_at.into()),
            updated_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(query_failed)?;

        request
            .approve(approval, decided_at)
            .map_err(|error| query_failed(DbErr::Type(error.to_string())))?;
        let data = Self::write_data(&ClientAuthorizationData::DeviceAuthorizationRequest(
            request,
        ))?;
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(decided_at).into()),
            )
            .filter(client_authorization::Column::Oid.eq(request_oid))
            .exec(&transaction)
            .await
            .map_err(query_failed)?;
        transaction.commit().await.map_err(query_failed)?;

        Ok(Some(relation_oid))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "deny_device_request"))]
    async fn deny_device_request(
        &self,
        request_oid: Uuid,
        user_oid: Uuid,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let Some(model) = Self::lock_row(&transaction, request_oid).await? else {
            return Ok(false);
        };
        if model.r#type != device_request_type()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= decided_at
        {
            return Ok(false);
        }

        let mut request = parse_device_request(model.data.clone())?;
        if request.deny(user_oid, decided_at).is_err() {
            return Ok(false);
        }

        let data = Self::write_data(&ClientAuthorizationData::DeviceAuthorizationRequest(
            request,
        ))?;
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(decided_at).into()),
            )
            .filter(client_authorization::Column::Oid.eq(request_oid))
            .exec(&transaction)
            .await
            .map_err(query_failed)?;
        transaction.commit().await.map_err(query_failed)?;

        Ok(true)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "consume_device_request_with_tokens"))]
    async fn consume_device_request_with_tokens(
        &self,
        request_oid: Uuid,
        records: Vec<PreparedAuthorizationRecord>,
        now: DateTime<Utc>,
    ) -> Result<DeviceConsumeOutcome, DeviceAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let Some(model) = Self::lock_row(&transaction, request_oid).await? else {
            return Ok(DeviceConsumeOutcome::NotRedeemable);
        };
        if model.r#type != device_request_type()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= now
        {
            return Ok(DeviceConsumeOutcome::NotRedeemable);
        }

        let mut request = parse_device_request(model.data.clone())?;
        if !request.is_approved() {
            return Ok(DeviceConsumeOutcome::NotRedeemable);
        }
        let Some(relation_oid) = request.device_authorization_oid else {
            return Ok(DeviceConsumeOutcome::NotRedeemable);
        };

        // Lock the relation as well: revocation and redemption must serialize
        // on it, otherwise a revocation that commits between this read and the
        // token insert would still let the redemption succeed. The request row
        // is locked first in every path (approve, deny, poll, redeem), and
        // revocation only ever locks the relation, so the lock order stays
        // consistent and cannot deadlock.
        let relation = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(relation_oid))
            .filter(client_authorization::Column::Type.eq(device_authorization_type()))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(query_failed)?;
        let relation_active = relation.is_some_and(|relation| {
            relation.revoked_at.is_none() && relation.expires_at.with_timezone(&Utc) > now
        });
        if !relation_active {
            return Ok(DeviceConsumeOutcome::AuthorizationRevoked);
        }

        request
            .consume()
            .map_err(|error| query_failed(DbErr::Type(error.to_string())))?;
        let data = Self::write_data(&ClientAuthorizationData::DeviceAuthorizationRequest(
            request,
        ))?;
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(data.into()),
            )
            .col_expr(
                client_authorization::Column::CompletedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(client_authorization::Column::Oid.eq(request_oid))
            .exec(&transaction)
            .await
            .map_err(query_failed)?;

        for record in &records {
            Self::insert_record(&transaction, model.client_id, record, now).await?;
        }
        transaction.commit().await.map_err(query_failed)?;

        Ok(DeviceConsumeOutcome::Consumed)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_device_authorization"))]
    async fn revoke_device_authorization(
        &self,
        device_authorization_oid: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError> {
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::Oid.eq(device_authorization_oid))
                    .add(client_authorization::Column::Type.eq(device_authorization_type()))
                    .add(client_authorization::Column::RevokedAt.is_null()),
            )
            .exec(&self.db)
            .await
            .map_err(query_failed)?;

        Ok(result.rows_affected == 1)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_device_authorizations_for_user"))]
    async fn revoke_device_authorizations_for_user(
        &self,
        user_oid: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, DeviceAuthorizationRepositoryError> {
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::Type.eq(device_authorization_type()))
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(json_field_equals("user_oid", &user_oid.to_string())),
            )
            .exec(&self.db)
            .await
            .map_err(query_failed)?;

        Ok(result.rows_affected)
    }
}
