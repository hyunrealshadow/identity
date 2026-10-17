//! Consuming an approved request and issuing its tokens in the same transaction.

use super::{
    DeviceAuthorizationRepositoryImpl, device_authorization_type, device_request_type,
    parse_device_request, query_failed, transition_failed,
};
use crate::database::entity::{
    client_authorization, client_authorization::Entity as ClientAuthorizationEntity,
};
use chrono::{DateTime, Utc};
use identity_domain::client_authorization::{
    ClientAuthorizationData, DeviceAuthorizationRepositoryError, DeviceConsumeOutcome,
    PreparedAuthorizationRecord,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait, sea_query::SimpleExpr,
};
use uuid::Uuid;

async fn insert_record<C: ConnectionTrait>(
    transaction: &C,
    client_id: i64,
    record: &PreparedAuthorizationRecord,
    now: DateTime<Utc>,
) -> Result<(), DeviceAuthorizationRepositoryError> {
    let type_ = record.data.authorization_type();
    let data = DeviceAuthorizationRepositoryImpl::write_data(&record.data)?;

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

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "consume_device_request_with_tokens"))]
pub(super) async fn consume_device_request_with_tokens(
    db: &DatabaseConnection,
    request_oid: Uuid,
    records: Vec<PreparedAuthorizationRecord>,
    now: DateTime<Utc>,
) -> Result<DeviceConsumeOutcome, DeviceAuthorizationRepositoryError> {
    let transaction = db.begin().await.map_err(query_failed)?;
    let Some(model) =
        DeviceAuthorizationRepositoryImpl::lock_row(&transaction, request_oid).await?
    else {
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

    request.consume().map_err(transition_failed)?;
    let data = DeviceAuthorizationRepositoryImpl::write_data(
        &ClientAuthorizationData::DeviceAuthorizationRequest(request),
    )?;
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
        insert_record(&transaction, model.client_id, record, now).await?;
    }
    transaction.commit().await.map_err(query_failed)?;

    Ok(DeviceConsumeOutcome::Consumed)
}
