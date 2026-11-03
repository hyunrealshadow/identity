//! Consuming an approved request and issuing its tokens in the same transaction.

use super::{
    DeviceAuthorizationRepositoryImpl, device_authorization_type, device_request_type,
    parse_device_request, query_failed, transition_failed,
};
use crate::database::{
    audit, authority_snapshot,
    entity::{
        client_authorization,
        client_authorization::{
            Column as ClientAuthorizationColumn, Entity as ClientAuthorizationEntity,
        },
    },
    repository::{authorization_lifecycle, client_authority, shared::lock_resource_rows},
};
use chrono::{DateTime, Utc};
use identity_domain::{
    authorization::{AuthorizationVersion, PolicyVersion},
    client_authorization::{
        ClientAuthorizationData, DeviceAuthorizationRepositoryError, DeviceConsumeOutcome,
        PreparedAuthorizationRecord,
    },
    user::UserOid,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait, sea_query::SimpleExpr,
};
use serde_json::Value;
use uuid::Uuid;

async fn insert_record<C: ConnectionTrait>(
    transaction: &C,
    client_id: i64,
    record: &PreparedAuthorizationRecord,
    now: DateTime<Utc>,
    client_fingerprint: PolicyVersion,
    authority_fingerprint: AuthorizationVersion,
) -> Result<(), DeviceAuthorizationRepositoryError> {
    let type_ = record.data.authorization_type();
    let mut data = DeviceAuthorizationRepositoryImpl::write_data(&record.data)?;
    if let Some(object) = data.as_object_mut() {
        object.insert(
            "_issuance_client_fingerprint".into(),
            client_fingerprint.as_uuid().to_string().into(),
        );
        object.insert(
            "_issuance_authority_fingerprint".into(),
            authority_fingerprint.as_uuid().to_string().into(),
        );
    }

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
    authorization_lifecycle::lock_authorization_issuance(&transaction)
        .await
        .map_err(query_failed)?;
    // Prepared records already carry the exact target selection used for the
    // JWT audience/scope. Lock those resource rows before the user and request
    // locks so a semantic withdrawal either sees the tokens this transaction
    // commits or blocks it before they are inserted.
    let mut target_resources = Vec::new();
    for record in &records {
        match &record.data {
            ClientAuthorizationData::AccessToken(data) => {
                target_resources.extend(data.resources.iter().cloned());
            }
            ClientAuthorizationData::RefreshToken(data) => {
                target_resources.extend(data.resources.iter().cloned());
            }
            _ => {}
        }
    }
    lock_resource_rows(&transaction, &target_resources)
        .await
        .map_err(query_failed)?;
    let subject = records
        .iter()
        .find_map(|record| match &record.data {
            ClientAuthorizationData::AccessToken(data) => data.user_oid.as_deref(),
            ClientAuthorizationData::RefreshToken(data) => Some(data.user_oid.as_str()),
            _ => None,
        })
        .ok_or_else(|| transition_failed("device token subject is missing"))?;
    let user_oid = Uuid::parse_str(subject).map_err(query_failed)?;
    DeviceAuthorizationRepositoryImpl::lock_live_user(&transaction, user_oid).await?;
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
    if request
        .approval
        .as_ref()
        .is_none_or(|approval| approval.user_oid != user_oid.to_string())
    {
        return Ok(DeviceConsumeOutcome::NotRedeemable);
    }
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
    let Some(relation) = ClientAuthorizationEntity::find()
        .filter(ClientAuthorizationColumn::Oid.eq(relation_oid))
        .filter(ClientAuthorizationColumn::Type.eq(device_authorization_type()))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(query_failed)?
    else {
        return Ok(DeviceConsumeOutcome::AuthorizationRevoked);
    };
    if relation.revoked_at.is_some() || relation.expires_at.with_timezone(&Utc) <= now {
        return Ok(DeviceConsumeOutcome::AuthorizationRevoked);
    }
    let issued_client_fingerprint = relation
        .data
        .get("_issuance_client_fingerprint")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let issued_authority_fingerprint = relation
        .data
        .get("_issuance_authority_fingerprint")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    if relation
        .data
        .get("_authority_withdrawn")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(DeviceConsumeOutcome::AuthorizationRevoked);
    }

    request.consume().map_err(transition_failed)?;
    let data = super::request_data_with_markers(&model.data, &request)?;
    ClientAuthorizationEntity::update_many()
        .col_expr(
            ClientAuthorizationColumn::Data,
            SimpleExpr::Value(data.into()),
        )
        .col_expr(
            ClientAuthorizationColumn::CompletedAt,
            SimpleExpr::Value(Some(now).into()),
        )
        .col_expr(
            ClientAuthorizationColumn::UpdatedAt,
            SimpleExpr::Value(Some(now).into()),
        )
        .filter(ClientAuthorizationColumn::Oid.eq(request_oid))
        .exec(&transaction)
        .await
        .map_err(query_failed)?;

    let (client_enabled, client_fingerprint) =
        client_authority::lock_live_client_boundary(&transaction, model.client_id)
            .await
            .map_err(query_failed)?;
    if !client_enabled || issued_client_fingerprint != Some(client_fingerprint.as_uuid()) {
        return Ok(DeviceConsumeOutcome::AuthorizationRevoked);
    }
    // Recompute after all inactive-user/device/client guards. A semantic
    // authority change between approval and redemption means the approved
    // grant is no longer the authority it was approved for.
    let authority_fingerprint =
        authority_snapshot::user_authority_fingerprint(&transaction, UserOid(user_oid))
            .await
            .map_err(query_failed)?;
    if issued_authority_fingerprint != Some(authority_fingerprint.as_uuid()) {
        return Ok(DeviceConsumeOutcome::AuthorizationRevoked);
    }
    for record in &records {
        insert_record(
            &transaction,
            model.client_id,
            record,
            now,
            client_fingerprint,
            authority_fingerprint,
        )
        .await?;
    }
    audit::record(
        &transaction,
        "device_authorization.consumed",
        "device_authorization",
        relation_oid,
    )
    .await
    .map_err(query_failed)?;
    transaction.commit().await.map_err(query_failed)?;

    Ok(DeviceConsumeOutcome::Consumed)
}
