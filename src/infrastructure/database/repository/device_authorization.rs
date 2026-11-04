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
    authorization::PolicyVersion,
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationRepositoryError,
        ClientAuthorizationType, DeviceAuthorizationApproval, DeviceAuthorizationRepository,
        DeviceAuthorizationRepositoryError, DeviceAuthorizationRequestData, DeviceConsumeOutcome,
        DevicePollOutcome, PreparedAuthorizationRecord,
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbBackend,
    DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, Statement, TransactionTrait,
    sea_query::{ExprTrait, SimpleExpr},
};
use serde_json::{Value, from_value, to_value};
use uuid::Uuid;

use super::{
    authorization_lifecycle,
    client_authorization::{serialize_data, to_domain},
};
use crate::database::{
    audit,
    entity::{
        client::{Column as ClientColumn, Entity as ClientEntity},
        client_authorization,
        client_authorization::{
            Column as ClientAuthorizationColumn, Entity as ClientAuthorizationEntity,
        },
    },
    query::json_text,
    repository::{client_authority, shared, shared::lock_resource_rows},
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
            ClientAuthorizationColumn::Data,
        ),
        field,
    )
    .eq(value)
}

fn json_field_is_null(field: &str) -> SimpleExpr {
    json_text(
        (
            client_authorization::Entity,
            ClientAuthorizationColumn::Data,
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

/// Issuance and withdrawal markers are not part of the typed request document.
/// Rewriting a request after a poll/claim/decision must carry them forward or a
/// later approval/redemption would lose its authority comparison and permanent
/// tombstone.
const PRESERVED_REQUEST_MARKERS: [&str; 3] = [
    "_issuance_client_fingerprint",
    "_issuance_authority_fingerprint",
    "_authority_withdrawn",
];

fn preserve_request_markers(original: &Value, updated: &mut Value) {
    let (Some(source), Some(target)) = (original.as_object(), updated.as_object_mut()) else {
        return;
    };
    for key in PRESERVED_REQUEST_MARKERS {
        if let Some(value) = source.get(key) {
            target.insert(key.to_owned(), value.clone());
        }
    }
}

fn request_data_with_markers(
    original: &Value,
    request: &DeviceAuthorizationRequestData,
) -> Result<Value, DeviceAuthorizationRepositoryError> {
    let mut updated = to_value(request).map_err(query_failed)?;
    preserve_request_markers(original, &mut updated);
    Ok(updated)
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
        // Acquire policy before authorization rows: disabling a client locks
        // its policy before revoking those rows in the same transaction.
        let Some(candidate) = ClientAuthorizationEntity::find()
            .filter(ClientAuthorizationColumn::Oid.eq(oid))
            .one(transaction)
            .await
            .map_err(query_failed)?
        else {
            return Ok(None);
        };
        Self::lock_live_client(transaction, candidate.client_id).await?;
        ClientAuthorizationEntity::find()
            .filter(ClientAuthorizationColumn::Oid.eq(oid))
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(query_failed)
    }

    async fn lock_live_client<C: ConnectionTrait>(
        transaction: &C,
        client_id: i64,
    ) -> Result<PolicyVersion, DeviceAuthorizationRepositoryError> {
        let (enabled, fingerprint) =
            client_authority::lock_live_client_boundary(transaction, client_id)
                .await
                .map_err(query_failed)?;
        if !enabled {
            return Err(query_failed(DbErr::RecordNotFound(
                "client is inactive".into(),
            )));
        }
        Ok(fingerprint)
    }

    /// Serialize with credential/account transitions and fail closed when the
    /// user is inactive. The authority fingerprint is computed separately after
    /// the remaining session/client guards, from the same transaction.
    async fn lock_live_user<C: ConnectionTrait>(
        transaction: &C,
        user: Uuid,
    ) -> Result<(), DeviceAuthorizationRepositoryError> {
        shared::lock_user_credentials(transaction, user.into())
            .await
            .map_err(query_failed)?;
        let row = transaction.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT u.enabled AND NOT u.locked AS active FROM \"user\" u WHERE u.oid=$1 FOR SHARE OF u",
            [user.into()])).await.map_err(query_failed)?
            .ok_or_else(|| query_failed(DbErr::RecordNotFound("user is inactive".into())))?;
        if !row.try_get::<bool>("", "active").map_err(query_failed)? {
            return Err(query_failed(DbErr::RecordNotFound(
                "user is inactive".into(),
            )));
        }
        Ok(())
    }

    async fn find_by_type(
        &self,
        oid: Uuid,
        type_: String,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError> {
        let Some((model, Some(client_model))) = ClientAuthorizationEntity::find()
            .filter(ClientAuthorizationColumn::Oid.eq(oid))
            .filter(ClientAuthorizationColumn::Type.eq(type_))
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
        authorization_lifecycle::lock_authorization_issuance(&transaction)
            .await
            .map_err(query_failed)?;
        // The request row will carry the actual target resources. Serialize
        // with resource semantic writers before touching the client policy or
        // inserting the request, in deterministic URI order.
        lock_resource_rows(&transaction, &data.resources)
            .await
            .map_err(query_failed)?;
        let client_model = ClientEntity::find()
            .filter(ClientColumn::Oid.eq(client_oid))
            .one(&transaction)
            .await
            .map_err(query_failed)?
            .ok_or_else(|| {
                query_failed(DbErr::RecordNotFound(format!(
                    "client {client_oid} not found"
                )))
            })?;

        let now = Utc::now();
        let client_fingerprint = Self::lock_live_client(&transaction, client_model.id).await?;
        // Release an expired owner immediately, even if the scheduled expiry
        // job has not reached it yet. The unique index still serializes active
        // owners across instances.
        ClientAuthorizationEntity::update_many()
            .col_expr(
                ClientAuthorizationColumn::Expired,
                SimpleExpr::Value(true.into()),
            )
            .col_expr(
                ClientAuthorizationColumn::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(ClientAuthorizationColumn::Type.eq(device_request_type()))
            .filter(json_field_equals("user_code", &data.user_code))
            .filter(ClientAuthorizationColumn::ExpiresAt.lte(now))
            .filter(ClientAuthorizationColumn::Expired.eq(false))
            .filter(ClientAuthorizationColumn::CompletedAt.is_null())
            .filter(ClientAuthorizationColumn::RevokedAt.is_null())
            .exec(&transaction)
            .await
            .map_err(query_failed)?;

        let mut stored_data = to_value(&data).map_err(query_failed)?;
        stored_data["_issuance_client_fingerprint"] =
            client_fingerprint.as_uuid().to_string().into();
        let model = client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(Uuid::new_v4()),
            client_id: Set(client_model.id),
            r#type: Set(device_request_type()),
            data: Set(stored_data),
            expires_at: Set(expires_at.into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            expired: Set(expires_at <= now),
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
        audit::record(
            &transaction,
            "device_authorization.requested",
            "device_authorization_request",
            model.oid,
        )
        .await
        .map_err(query_failed)?;
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
            .filter(ClientAuthorizationColumn::Type.eq(device_request_type()))
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
            .filter(ClientAuthorizationColumn::Type.eq(device_request_type()))
            .filter(ClientAuthorizationColumn::CompletedAt.is_null())
            .filter(ClientAuthorizationColumn::RevokedAt.is_null())
            .filter(ClientAuthorizationColumn::Expired.eq(false))
            .filter(ClientAuthorizationColumn::ExpiresAt.gt(Utc::now()))
            // A claimed code is semantically consumed: only an unclaimed
            // request can still be answered with the code it advertises.
            .filter(json_field_is_null("claimed_login_oid"))
            .filter(json_field_equals("user_code", user_code))
            .order_by_desc(ClientAuthorizationColumn::CreatedAt)
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
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                ClientAuthorizationColumn::RevokedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .col_expr(
                ClientAuthorizationColumn::UpdatedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .filter(
                Condition::all()
                    .add(ClientAuthorizationColumn::Oid.eq(device_authorization_oid))
                    .add(ClientAuthorizationColumn::Type.eq(device_authorization_type()))
                    .add(ClientAuthorizationColumn::RevokedAt.is_null()),
            )
            .exec(&transaction)
            .await
            .map_err(query_failed)?;
        let revoked = result.rows_affected == 1;
        if revoked {
            audit::record(
                &transaction,
                "device_authorization.revoked",
                "device_authorization",
                device_authorization_oid,
            )
            .await
            .map_err(query_failed)?;
        }
        transaction.commit().await.map_err(query_failed)?;

        Ok(revoked)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "revoke_device_authorizations_for_user"))]
    async fn revoke_device_authorizations_for_user(
        &self,
        user_oid: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, DeviceAuthorizationRepositoryError> {
        let transaction = self.db.begin().await.map_err(query_failed)?;
        let revoked = ClientAuthorizationEntity::update_many()
            .col_expr(
                ClientAuthorizationColumn::RevokedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .col_expr(
                ClientAuthorizationColumn::UpdatedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .filter(
                Condition::all()
                    .add(ClientAuthorizationColumn::Type.eq(device_authorization_type()))
                    .add(ClientAuthorizationColumn::RevokedAt.is_null())
                    .add(json_field_equals("user_oid", &user_oid.to_string())),
            )
            .exec_with_returning(&transaction)
            .await
            .map_err(query_failed)?;
        for relation in &revoked {
            audit::record(
                &transaction,
                "device_authorization.revoked",
                "device_authorization",
                relation.oid,
            )
            .await
            .map_err(query_failed)?;
        }
        let count = revoked.len() as u64;
        transaction.commit().await.map_err(query_failed)?;

        Ok(count)
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
