//! Device authorization persistence (RFC 8628) on `client_authorization`.
//!
//! Requests and the relations they create share the table with the other
//! authorization artifacts and are distinguished by their `type`; the
//! concurrency guarantees come from row locks and partial unique indexes, not
//! from process-local state.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
    sea_query::{Expr, SimpleExpr},
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
/// `m20260913_000001_device_authorization_indexes`.
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
    Expr::cust_with_values(
        format!(r#"("client_authorization"."data"->>'{field}') = $1"#),
        [value],
    )
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
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
        }
        .insert(transaction)
        .await
        .map_err(query_failed)?;

        Ok(())
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
        let model = client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(Uuid::new_v4()),
            client_id: Set(client_model.id),
            r#type: Set(device_request_type()),
            data: Set(serde_json::to_value(&data).map_err(query_failed)?),
            expires_at: Set(expires_at.into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
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
            created_at: Set(decided_at.into()),
            updated_at: Set(Some(decided_at.into())),
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

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "delete_expired_device_requests"))]
    async fn delete_expired_device_requests(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, DeviceAuthorizationRepositoryError> {
        let result = ClientAuthorizationEntity::delete_many()
            .filter(client_authorization::Column::Type.eq(device_request_type()))
            .filter(client_authorization::Column::ExpiresAt.lte(now))
            .exec(&self.db)
            .await
            .map_err(query_failed)?;

        Ok(result.rows_affected)
    }
}

/// PostgreSQL integration tests for the device authorization state machine.
///
/// Skipped by default because they need a live database; run them with
/// `IDENTITY_TEST_DATABASE_URL=postgres://… cargo test -p identity-infrastructure
/// --lib device_authorization -- --ignored`. They migrate the target database
/// and clean up the client rows they create.
#[cfg(test)]
mod postgres_tests {
    use super::*;
    use crate::database::entity::client;
    use identity_domain::client_authorization::{
        AccessTokenData, ClientAuthorizationData, DeviceAuthorizationRequestData,
        DeviceRequestStatus,
    };
    use identity_domain::openid_connect::ScopeSet;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait, PaginatorTrait};

    /// Isolated schema so the tests never touch rows of the target database.
    const TEST_SCHEMA: &str = "identity_device_test";

    async fn test_db() -> DatabaseConnection {
        let url = std::env::var("IDENTITY_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("set IDENTITY_TEST_DATABASE_URL to run device authorization tests");
        let admin = Database::connect(ConnectOptions::new(url.clone()))
            .await
            .expect("connect test database");
        admin
            .execute_unprepared(&format!("CREATE SCHEMA IF NOT EXISTS {TEST_SCHEMA}"))
            .await
            .expect("create test schema");
        drop(admin);

        let mut options = ConnectOptions::new(url);
        options.set_schema_search_path(TEST_SCHEMA);
        let db = Database::connect(options)
            .await
            .expect("connect test schema");
        crate::database::migrate(&db)
            .await
            .expect("migrate test database");
        db
    }

    async fn create_client(db: &DatabaseConnection, oid: ClientOid) {
        client::ActiveModel {
            oid: Set(oid),
            protocol: Set("openid_connect".to_owned()),
            name: Set("Device Test Client".to_owned()),
            ..Default::default()
        }
        .insert(db)
        .await
        .expect("insert test client");
    }

    async fn drop_client(db: &DatabaseConnection, oid: ClientOid) {
        client::Entity::delete_many()
            .filter(client::Column::Oid.eq(oid))
            .exec(db)
            .await
            .expect("delete test client");
    }

    fn new_client_oid() -> ClientOid {
        Uuid::new_v4()
    }

    fn request_data(
        device_code: &str,
        user_code: &str,
        interval_seconds: i64,
    ) -> DeviceAuthorizationRequestData {
        DeviceAuthorizationRequestData {
            scope: "openid offline_access".to_owned(),
            device_code_digest: identity_domain::client_authorization::device_code_digest(
                device_code,
            ),
            user_code: user_code.to_owned(),
            user_code_display: identity_domain::client_authorization::format_user_code(user_code),
            interval_seconds,
            slow_down_seconds: 0,
            last_polled_at: None,
            status: DeviceRequestStatus::Pending,
            approval: None,
            denied_by_user_oid: None,
            decided_at: None,
            device_authorization_oid: None,
        }
    }

    fn approval() -> DeviceAuthorizationApproval {
        DeviceAuthorizationApproval {
            user_oid: Uuid::new_v4().to_string(),
            approved_scope: "openid offline_access".to_owned(),
            auth_time: Some(1_700_000_000),
            acr: Some("urn:identity:acr:aal1".to_owned()),
            amr: vec!["pwd".to_owned()],
            device_authorization_oid: Uuid::new_v4(),
        }
    }

    fn access_token_record(user_oid: &str) -> PreparedAuthorizationRecord {
        PreparedAuthorizationRecord {
            oid: Uuid::new_v4(),
            data: ClientAuthorizationData::AccessToken(AccessTokenData {
                scope: "openid offline_access".to_owned(),
                user_oid: user_oid.to_owned(),
                session_oid: None,
                protected_session_id: None,
                authorization_code_oid: None,
                device_authorization_oid: None,
            }),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        }
    }

    async fn count_rows(db: &DatabaseConnection, oid: Uuid) -> u64 {
        ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .count(db)
            .await
            .expect("count rows")
    }

    async fn relation_count(db: &DatabaseConnection, client_oid: ClientOid) -> u64 {
        ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Type.eq(device_authorization_type()))
            .inner_join(ClientEntity)
            .filter(client::Column::Oid.eq(client_oid))
            .count(db)
            .await
            .expect("count relations")
    }

    /// Codes are unique per call so a test never depends on rows another test
    /// (or a failed earlier run) left behind.
    fn unique_code(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4())
    }

    async fn create_pending_request(
        repository: &DeviceAuthorizationRepositoryImpl,
        client_oid: ClientOid,
        device_code: &str,
        user_code: &str,
    ) -> Uuid {
        repository
            .create_device_request(
                client_oid,
                request_data(device_code, user_code, 5),
                Utc::now() + chrono::Duration::minutes(10),
            )
            .await
            .expect("create device request")
            .oid
    }

    async fn insert_request(
        db: &DatabaseConnection,
        client_oid: ClientOid,
        data: DeviceAuthorizationRequestData,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientAuthorization, DeviceAuthorizationRepositoryError> {
        DeviceAuthorizationRepositoryImpl::new(db.clone())
            .create_device_request(client_oid, data, expires_at)
            .await
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn user_code_is_unique_among_active_requests() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        // Both requests intentionally share one user code.
        let user_code = unique_code("CODE");

        let first = insert_request(
            &db,
            client_oid,
            request_data(&unique_code("device-a"), &user_code, 5),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .expect("first request");

        let conflicting = insert_request(
            &db,
            client_oid,
            request_data(&unique_code("device-b"), &user_code, 5),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await;
        assert!(matches!(
            conflicting,
            Err(DeviceAuthorizationRepositoryError::UserCodeConflict)
        ));

        // Completing the first request releases its user code.
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::CompletedAt,
                SimpleExpr::Value(Some(Utc::now()).into()),
            )
            .filter(client_authorization::Column::Oid.eq(first.oid))
            .exec(&db)
            .await
            .expect("complete first request");

        insert_request(
            &db,
            client_oid,
            request_data(&unique_code("device-c"), &user_code, 5),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .expect("user code is reusable once the request is completed");

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn approving_a_denied_request_is_rejected() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        assert!(
            repository
                .deny_device_request(request_oid, Uuid::new_v4(), Utc::now())
                .await
                .expect("deny request")
        );

        let approved = repository
            .approve_device_request(request_oid, approval(), Utc::now())
            .await
            .expect("approve after deny");
        assert!(approved.is_none());
        assert_eq!(relation_count(&db, client_oid).await, 0);

        let stored = repository
            .find_device_request_by_oid(request_oid)
            .await
            .expect("load request")
            .expect("request exists");
        let ClientAuthorizationData::DeviceAuthorizationRequest(data) = stored.data else {
            panic!("expected a device request");
        };
        assert_eq!(data.status, DeviceRequestStatus::Denied);
        assert!(data.approval.is_none());

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn concurrent_approvals_create_exactly_one_relation() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let (first, second) = tokio::join!(
            repository.approve_device_request(request_oid, approval(), Utc::now()),
            repository.approve_device_request(request_oid, approval(), Utc::now()),
        );
        let first = first.expect("first approval");
        let second = second.expect("second approval");

        assert_ne!(first.is_some(), second.is_some());
        assert_eq!(relation_count(&db, client_oid).await, 1);

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn concurrent_redemptions_issue_tokens_once() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let approval = approval();
        let user_oid = approval.user_oid.clone();
        repository
            .approve_device_request(request_oid, approval, Utc::now())
            .await
            .expect("approve request")
            .expect("relation created");

        let first = access_token_record(&user_oid);
        let second = access_token_record(&user_oid);
        let (first_result, second_result) = tokio::join!(
            repository.consume_device_request_with_tokens(
                request_oid,
                vec![first.clone()],
                Utc::now()
            ),
            repository.consume_device_request_with_tokens(
                request_oid,
                vec![second.clone()],
                Utc::now()
            ),
        );
        let first_result = first_result.expect("first redemption");
        let second_result = second_result.expect("second redemption");

        let issued = [first_result, second_result]
            .into_iter()
            .filter(|outcome| *outcome == DeviceConsumeOutcome::Consumed)
            .count();
        assert_eq!(issued, 1);

        let stored_first = count_rows(&db, first.oid).await;
        let stored_second = count_rows(&db, second.oid).await;
        assert_eq!(stored_first + stored_second, 1);

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn revoked_relation_blocks_redemption_without_writing_tokens() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let approval = approval();
        let relation_oid = approval.device_authorization_oid;
        let user_oid = approval.user_oid.clone();
        repository
            .approve_device_request(request_oid, approval, Utc::now())
            .await
            .expect("approve request")
            .expect("relation created");
        assert!(
            repository
                .revoke_device_authorization(relation_oid, Utc::now())
                .await
                .expect("revoke relation")
        );

        let record = access_token_record(&user_oid);
        let outcome = repository
            .consume_device_request_with_tokens(request_oid, vec![record.clone()], Utc::now())
            .await
            .expect("redemption attempt");

        assert_eq!(outcome, DeviceConsumeOutcome::AuthorizationRevoked);
        assert_eq!(count_rows(&db, record.oid).await, 0);

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn poll_schedule_accumulates_slow_downs() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let start = Utc::now();
        assert_eq!(
            repository
                .record_device_poll(request_oid, start)
                .await
                .expect("first poll"),
            DevicePollOutcome::Accepted
        );
        assert_eq!(
            repository
                .record_device_poll(request_oid, start + chrono::Duration::seconds(1))
                .await
                .expect("early poll"),
            DevicePollOutcome::TooFrequent
        );
        // 5 advertised seconds plus the 5 seconds accumulated by the early poll.
        assert_eq!(
            repository
                .record_device_poll(request_oid, start + chrono::Duration::seconds(9))
                .await
                .expect("still early"),
            DevicePollOutcome::TooFrequent
        );
        assert_eq!(
            repository
                .record_device_poll(request_oid, start + chrono::Duration::seconds(20))
                .await
                .expect("on time"),
            DevicePollOutcome::Accepted
        );

        let stored = repository
            .find_device_request_by_oid(request_oid)
            .await
            .expect("load request")
            .expect("request exists");
        let ClientAuthorizationData::DeviceAuthorizationRequest(data) = stored.data else {
            panic!("expected a device request");
        };
        assert_eq!(data.slow_down_seconds, 10);
        assert_eq!(data.effective_interval_seconds(), 15);

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn expired_request_cannot_be_approved_or_redeemed() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request = insert_request(
            &db,
            client_oid,
            request_data(&unique_code("device"), &unique_code("CODE"), 5),
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("create expired request");

        let approved = repository
            .approve_device_request(request.oid, approval(), Utc::now())
            .await
            .expect("approve expired request");
        assert!(approved.is_none());

        let outcome = repository
            .consume_device_request_with_tokens(request.oid, vec![], Utc::now())
            .await
            .expect("redeem expired request");
        assert_eq!(outcome, DeviceConsumeOutcome::NotRedeemable);

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn approved_scope_must_stay_inside_the_requested_scope() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let mut escalated = approval();
        escalated.approved_scope = "openid offline_access account".to_owned();
        let result = repository
            .approve_device_request(request_oid, escalated, Utc::now())
            .await;

        assert!(matches!(
            result,
            Err(DeviceAuthorizationRepositoryError::ScopeNotGrantable)
        ));
        assert_eq!(relation_count(&db, client_oid).await, 0);

        let narrowed = approval();
        let mut narrowed = narrowed;
        narrowed.approved_scope = "openid".to_owned();
        repository
            .approve_device_request(request_oid, narrowed, Utc::now())
            .await
            .expect("approve narrowed scope")
            .expect("relation created");

        let scope: ScopeSet = ScopeSet::parse("openid").expect("parse scope");
        assert!(scope.contains_openid());

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn revoking_for_a_user_leaves_other_accounts_alone() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());

        let first_user = Uuid::new_v4();
        let second_user = Uuid::new_v4();
        let mut first_relations = Vec::new();
        let mut second_relations = Vec::new();
        for user_oid in [first_user, second_user] {
            let request_oid = create_pending_request(
                &repository,
                client_oid,
                &unique_code("device"),
                &unique_code("CODE"),
            )
            .await;
            let mut approval = approval();
            approval.user_oid = user_oid.to_string();
            repository
                .approve_device_request(request_oid, approval.clone(), Utc::now())
                .await
                .expect("approve request")
                .expect("relation created");
            if user_oid == first_user {
                first_relations.push(approval.device_authorization_oid);
            } else {
                second_relations.push(approval.device_authorization_oid);
            }
        }

        let revoked = repository
            .revoke_device_authorizations_for_user(first_user, Utc::now())
            .await
            .expect("revoke first user");

        assert_eq!(revoked, 1);
        for oid in first_relations {
            let relation = repository
                .find_device_authorization_by_oid(oid)
                .await
                .expect("load relation")
                .expect("relation exists");
            assert!(
                relation.revoked_at.is_some(),
                "the revoked relation is marked"
            );
        }
        for oid in second_relations {
            let relation = repository
                .find_device_authorization_by_oid(oid)
                .await
                .expect("load relation")
                .expect("relation exists");
            assert!(
                relation.revoked_at.is_none(),
                "another account keeps its authorization"
            );
        }

        drop_client(&db, client_oid).await;
    }

    /// Reproduces the revocation/redemption interleaving on two connections:
    /// the redemption must wait for the relation lock, then observe the
    /// revocation instead of issuing tokens.
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_revocation_committed_during_redemption_blocks_the_tokens() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let approval = approval();
        let relation_oid = approval.device_authorization_oid;
        let user_oid = approval.user_oid.clone();
        repository
            .approve_device_request(request_oid, approval, Utc::now())
            .await
            .expect("approve request")
            .expect("relation created");

        // Connection A holds the relation lock, exactly like an in-flight
        // revocation does before it commits.
        let revoker = db.begin().await.expect("begin revocation transaction");
        ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(relation_oid))
            .lock_exclusive()
            .one(&revoker)
            .await
            .expect("lock relation");

        let record = access_token_record(&user_oid);
        let redemption = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let record_for_redemption = record.clone();
        let redemption = tokio::spawn(async move {
            redemption
                .consume_device_request_with_tokens(
                    request_oid,
                    vec![record_for_redemption],
                    Utc::now(),
                )
                .await
        });

        // Give the redemption a chance to reach the relation read: without the
        // lock it would already commit here.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            count_rows(&db, record.oid).await,
            0,
            "the redemption must not commit while the relation is locked"
        );

        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(Some(Utc::now()).into()),
            )
            .filter(client_authorization::Column::Oid.eq(relation_oid))
            .exec(&revoker)
            .await
            .expect("revoke relation");
        revoker.commit().await.expect("commit revocation");

        let outcome = redemption
            .await
            .expect("redemption task")
            .expect("redemption result");
        assert_eq!(outcome, DeviceConsumeOutcome::AuthorizationRevoked);
        assert_eq!(
            count_rows(&db, record.oid).await,
            0,
            "a revoked authorization issues no tokens"
        );

        drop_client(&db, client_oid).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_failed_redemption_rolls_back_and_can_be_retried() {
        let db = test_db().await;
        let client_oid = new_client_oid();
        create_client(&db, client_oid).await;
        let repository = DeviceAuthorizationRepositoryImpl::new(db.clone());
        let request_oid = create_pending_request(
            &repository,
            client_oid,
            &unique_code("device"),
            &unique_code("CODE"),
        )
        .await;

        let approval = approval();
        let relation_oid = approval.device_authorization_oid;
        let user_oid = approval.user_oid.clone();
        repository
            .approve_device_request(request_oid, approval, Utc::now())
            .await
            .expect("approve request")
            .expect("relation created");

        // A row that already occupies an oid makes the second insert of the
        // redemption fail after the request row was already updated.
        let taken = access_token_record(&user_oid);
        client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(taken.oid),
            client_id: Set(client::Entity::find()
                .filter(client::Column::Oid.eq(client_oid))
                .one(&db)
                .await
                .expect("load client")
                .expect("client exists")
                .id),
            r#type: Set(ClientAuthorizationType::DeviceAuthorization.to_string()),
            data: Set(serde_json::json!({})),
            expires_at: Set((Utc::now() + chrono::Duration::minutes(5)).into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            created_at: Set(Utc::now().into()),
            updated_at: Set(Some(Utc::now().into())),
        }
        .insert(&db)
        .await
        .expect("insert conflicting row");

        let fresh = access_token_record(&user_oid);
        let outcome = repository
            .consume_device_request_with_tokens(request_oid, vec![fresh.clone(), taken], Utc::now())
            .await;

        assert!(outcome.is_err(), "the conflicting insert must fail");
        assert_eq!(
            count_rows(&db, fresh.oid).await,
            0,
            "a rolled back redemption writes no token rows"
        );
        let stored = repository
            .find_device_request_by_oid(request_oid)
            .await
            .expect("load request")
            .expect("request exists");
        assert_eq!(stored.completed_at, None);
        let ClientAuthorizationData::DeviceAuthorizationRequest(data) = stored.data else {
            panic!("expected a device request");
        };
        assert_eq!(data.status, DeviceRequestStatus::Approved);

        // Retrying with fresh records succeeds and commits exactly one set.
        let retry = access_token_record(&user_oid);
        let outcome = repository
            .consume_device_request_with_tokens(request_oid, vec![retry.clone()], Utc::now())
            .await
            .expect("retry redemption");
        assert_eq!(outcome, DeviceConsumeOutcome::Consumed);
        assert_eq!(count_rows(&db, retry.oid).await, 1);
        assert!(
            repository
                .find_device_authorization_by_oid(relation_oid)
                .await
                .expect("load relation")
                .is_some()
        );

        drop_client(&db, client_oid).await;
    }
}
