//! Atomic request transitions: login claim, polling schedule, and approval or denial.

use super::{
    DeviceAuthorizationRepositoryImpl, device_authorization_type, device_request_type,
    parse_device_request, query_failed, transition_failed,
};
use crate::database::{
    entity::{
        client_authorization, client_authorization::Entity as ClientAuthorizationEntity, login,
        session,
    },
    repository::shared::non_expiring_timestamp,
};
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::SessionOid,
    client_authorization::{
        ClientAuthorizationData, DeviceAuthorizationApproval, DeviceAuthorizationData,
        DeviceAuthorizationRepositoryError, DevicePollOutcome, SLOW_DOWN_INCREMENT_SECONDS,
    },
    openid_connect::ScopeSet,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
    sea_query::{Expr, SimpleExpr},
};
use serde_json::to_value;
use uuid::Uuid;

pub(super) async fn claim_device_request(
    db: &DatabaseConnection,
    request_oid: Uuid,
    login_oid: Uuid,
    session_oid: SessionOid,
    now: DateTime<Utc>,
) -> Result<bool, DeviceAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_failed)?;
    let Some(request) =
        DeviceAuthorizationRepositoryImpl::lock_row(&transaction, request_oid).await?
    else {
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
        let same = login.session_id == Some(session.id) && login.user_id == Some(session.user_id);
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
            Expr::value(to_value(data).map_err(query_failed)?),
        )
        .col_expr(client_authorization::Column::UpdatedAt, Expr::value(now))
        .filter(client_authorization::Column::Id.eq(request.id))
        .exec(&transaction)
        .await
        .map_err(query_failed)?;
    transaction.commit().await.map_err(query_failed)?;
    Ok(true)
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "record_device_poll"))]
pub(super) async fn record_device_poll(
    db: &DatabaseConnection,
    request_oid: Uuid,
    polled_at: DateTime<Utc>,
) -> Result<DevicePollOutcome, DeviceAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_failed)?;
    let Some(model) =
        DeviceAuthorizationRepositoryImpl::lock_row(&transaction, request_oid).await?
    else {
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

    let effective_interval = Duration::seconds(request.effective_interval_seconds());
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

    let data = DeviceAuthorizationRepositoryImpl::write_data(
        &ClientAuthorizationData::DeviceAuthorizationRequest(request),
    )?;
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
pub(super) async fn approve_device_request(
    db: &DatabaseConnection,
    request_oid: Uuid,
    approval: DeviceAuthorizationApproval,
    decided_at: DateTime<Utc>,
) -> Result<Option<Uuid>, DeviceAuthorizationRepositoryError> {
    let approved_scope = ScopeSet::parse(&approval.approved_scope).map_err(query_failed)?;
    let transaction = db.begin().await.map_err(query_failed)?;
    let Some(model) =
        DeviceAuthorizationRepositoryImpl::lock_row(&transaction, request_oid).await?
    else {
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
        data: Set(to_value(&relation).map_err(query_failed)?),
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
        .map_err(transition_failed)?;
    let data = DeviceAuthorizationRepositoryImpl::write_data(
        &ClientAuthorizationData::DeviceAuthorizationRequest(request),
    )?;
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
pub(super) async fn deny_device_request(
    db: &DatabaseConnection,
    request_oid: Uuid,
    user_oid: Uuid,
    decided_at: DateTime<Utc>,
) -> Result<bool, DeviceAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_failed)?;
    let Some(model) =
        DeviceAuthorizationRepositoryImpl::lock_row(&transaction, request_oid).await?
    else {
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

    let data = DeviceAuthorizationRepositoryImpl::write_data(
        &ClientAuthorizationData::DeviceAuthorizationRequest(request),
    )?;
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
