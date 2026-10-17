//! Device authorization persistence (RFC 8628) on `client_authorization`.
//!
//! Requests and the relations they create share the table with the other
//! authorization artifacts and are distinguished by their `type`; the
//! concurrency guarantees come from row locks and partial unique indexes, not
//! from process-local state.

use std::{error::Error, fmt::Display};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::{
    auth::SessionOid,
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationRepositoryError,
        ClientAuthorizationType, DeviceAuthorizationApproval, DeviceAuthorizationRepository,
        DeviceAuthorizationRepositoryError, DeviceAuthorizationRequestData, DeviceConsumeOutcome,
        DevicePollOutcome, PreparedAuthorizationRecord,
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
    sea_query::{ExprTrait, SimpleExpr},
};
use serde_json::{Value, from_value, to_value};
use uuid::Uuid;

use super::client_authorization::{serialize_data, to_domain};
use crate::database::{
    entity::{
        client, client::Entity as ClientEntity, client_authorization,
        client_authorization::Entity as ClientAuthorizationEntity,
    },
    query::json_text,
};

mod redemption;
mod request_state;

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

fn query_failed(error: impl Error + Send + Sync + 'static) -> DeviceAuthorizationRepositoryError {
    DeviceAuthorizationRepositoryError::QueryFailed(Box::new(error))
}

fn transition_failed(error: impl Display) -> DeviceAuthorizationRepositoryError {
    query_failed(DbErr::Type(error.to_string()))
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
    data: Value,
) -> Result<DeviceAuthorizationRequestData, DeviceAuthorizationRepositoryError> {
    from_value(data).map_err(query_failed)
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
    ) -> Result<Value, DeviceAuthorizationRepositoryError> {
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
}

#[async_trait]
impl DeviceAuthorizationRepository for DeviceAuthorizationRepositoryImpl {
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
            data: Set(to_value(&data).map_err(query_failed)?),
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

    async fn claim_device_request(
        &self,
        request_oid: Uuid,
        login_oid: Uuid,
        session_oid: SessionOid,
        now: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError> {
        request_state::claim_device_request(&self.db, request_oid, login_oid, session_oid, now)
            .await
    }

    async fn record_device_poll(
        &self,
        request_oid: Uuid,
        polled_at: DateTime<Utc>,
    ) -> Result<DevicePollOutcome, DeviceAuthorizationRepositoryError> {
        request_state::record_device_poll(&self.db, request_oid, polled_at).await
    }

    async fn approve_device_request(
        &self,
        request_oid: Uuid,
        approval: DeviceAuthorizationApproval,
        decided_at: DateTime<Utc>,
    ) -> Result<Option<Uuid>, DeviceAuthorizationRepositoryError> {
        request_state::approve_device_request(&self.db, request_oid, approval, decided_at).await
    }

    async fn deny_device_request(
        &self,
        request_oid: Uuid,
        user_oid: Uuid,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError> {
        request_state::deny_device_request(&self.db, request_oid, user_oid, decided_at).await
    }

    async fn consume_device_request_with_tokens(
        &self,
        request_oid: Uuid,
        records: Vec<PreparedAuthorizationRecord>,
        now: DateTime<Utc>,
    ) -> Result<DeviceConsumeOutcome, DeviceAuthorizationRepositoryError> {
        redemption::consume_device_request_with_tokens(&self.db, request_oid, records, now).await
    }
}
