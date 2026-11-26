use chrono::{DateTime, Utc};
use identity_domain::{
    audit::{AuditEventOrder, AuditEventOrderDirection, AuditEventOrderField, AuditEventSortKey},
    time_zone::TimeZone,
};
use serde::{Deserialize, Serialize};

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::audit},
    pagination::{protect_json_cursors, sha256_hex, unprotect_json_cursor},
};

pub const AUDIT_CURSOR_PURPOSE: &str = "cursor:audit";
const AUDIT_CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCursorPayload {
    pub version: u8,
    pub filter_hash: String,
    pub snapshot_at_micros: i64,
    pub order_field: u8,
    pub order_direction: u8,
    pub occurred_at_micros: i64,
    pub id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAuditCursor {
    pub sort_key: AuditEventSortKey,
    pub snapshot_at: DateTime<Utc>,
}

#[must_use]
pub fn audit_filter_hash(
    normalized_query: &str,
    time_zone: TimeZone,
    order: AuditEventOrder,
) -> String {
    let mut bytes = Vec::with_capacity(normalized_query.len() + time_zone.name().len() + 4);
    bytes.extend_from_slice(normalized_query.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(time_zone.name().as_bytes());
    bytes.push(0);
    bytes.push(encode_order_field(order.field));
    bytes.push(encode_order_dir(order.direction));
    sha256_hex(&bytes)
}

pub async fn encode_cursors(
    protector: &dyn DataProtector,
    filter_hash: &str,
    snapshot_at: DateTime<Utc>,
    order: AuditEventOrder,
    keys: &[AuditEventSortKey],
) -> Result<Vec<String>, AppError> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let snapshot_at_micros = snapshot_at.timestamp_micros();
    let order_field = encode_order_field(order.field);
    let order_direction = encode_order_dir(order.direction);

    let payloads = keys
        .iter()
        .map(|key| AuditCursorPayload {
            version: AUDIT_CURSOR_VERSION,
            filter_hash: filter_hash.to_owned(),
            snapshot_at_micros,
            order_field,
            order_direction,
            occurred_at_micros: key.occurred_at.timestamp_micros(),
            id: key.id,
        })
        .collect::<Vec<_>>();

    protect_json_cursors(protector, AUDIT_CURSOR_PURPOSE, &payloads)
        .await
        .map_err(AppError::internal)
}

pub async fn decode_cursor(
    protector: &dyn DataProtector,
    token: &str,
    expected_filter_hash: &str,
    expected_order: AuditEventOrder,
) -> Result<DecodedAuditCursor, AppError> {
    let payload: AuditCursorPayload = unprotect_json_cursor(protector, AUDIT_CURSOR_PURPOSE, token)
        .await
        .map_err(|_| audit::error::InvalidCursor)?;

    if payload.version != AUDIT_CURSOR_VERSION
        || payload.filter_hash != expected_filter_hash
        || payload.order_field != encode_order_field(expected_order.field)
        || payload.order_direction != encode_order_dir(expected_order.direction)
    {
        return Err(audit::error::InvalidCursor.into());
    }

    let snapshot_at = DateTime::from_timestamp_micros(payload.snapshot_at_micros)
        .ok_or(audit::error::InvalidCursor)?;
    let occurred_at = DateTime::from_timestamp_micros(payload.occurred_at_micros)
        .ok_or(audit::error::InvalidCursor)?;

    Ok(DecodedAuditCursor {
        sort_key: AuditEventSortKey {
            occurred_at,
            id: payload.id,
        },
        snapshot_at,
    })
}

const fn encode_order_field(field: AuditEventOrderField) -> u8 {
    match field {
        AuditEventOrderField::OccurredAt => 0,
    }
}

const fn encode_order_dir(direction: AuditEventOrderDirection) -> u8 {
    match direction {
        AuditEventOrderDirection::Asc => 0,
        AuditEventOrderDirection::Desc => 1,
    }
}
