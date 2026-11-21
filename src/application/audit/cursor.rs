use chrono::{DateTime, Utc};
use identity_domain::{
    audit::{AuditEventOrder, AuditEventOrderDirection, AuditEventOrderField, AuditEventSortKey},
    time_zone::TimeZone,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::audit::AuditErrorCode},
};

pub const AUDIT_CURSOR_PURPOSE: &str = "graphql:cursor:audit";
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
    let mut hasher = Sha256::new();
    hasher.update(normalized_query.as_bytes());
    hasher.update([0]);
    hasher.update(time_zone.name().as_bytes());
    hasher.update([
        0,
        encode_order_field(order.field),
        encode_order_dir(order.direction),
    ]);
    hex_encode(&hasher.finalize())
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

    let mut plaintexts = Vec::with_capacity(keys.len());
    for key in keys {
        let payload = AuditCursorPayload {
            version: AUDIT_CURSOR_VERSION,
            filter_hash: filter_hash.to_owned(),
            snapshot_at_micros,
            order_field,
            order_direction,
            occurred_at_micros: key.occurred_at.timestamp_micros(),
            id: key.id,
        };
        let bytes = serde_json::to_vec(&payload).map_err(AppError::internal)?;
        plaintexts.push(bytes);
    }

    protector
        .protect_many(AUDIT_CURSOR_PURPOSE, &plaintexts)
        .await
        .map_err(AppError::internal)
}

pub async fn decode_cursor(
    protector: &dyn DataProtector,
    token: &str,
    expected_filter_hash: &str,
    expected_order: AuditEventOrder,
) -> Result<DecodedAuditCursor, AppError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(AppError::from_code(AuditErrorCode::InvalidCursor));
    }
    let bytes = protector
        .unprotect(AUDIT_CURSOR_PURPOSE, trimmed)
        .await
        .map_err(|_| AppError::from_code(AuditErrorCode::InvalidCursor))?;
    let payload: AuditCursorPayload = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::from_code(AuditErrorCode::InvalidCursor))?;

    if payload.version != AUDIT_CURSOR_VERSION
        || payload.filter_hash != expected_filter_hash
        || payload.order_field != encode_order_field(expected_order.field)
        || payload.order_direction != encode_order_dir(expected_order.direction)
    {
        return Err(AppError::from_code(AuditErrorCode::InvalidCursor));
    }

    let snapshot_at = DateTime::from_timestamp_micros(payload.snapshot_at_micros)
        .ok_or_else(|| AppError::from_code(AuditErrorCode::InvalidCursor))?;
    let occurred_at = DateTime::from_timestamp_micros(payload.occurred_at_micros)
        .ok_or_else(|| AppError::from_code(AuditErrorCode::InvalidCursor))?;

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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
