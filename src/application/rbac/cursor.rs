//! Bounded, filter-bound keyset cursors for every RBAC management list.
//!
//! The cursor is protected by the existing [`DataProtector`] port and carries a
//! digest of the normalized filter plus the order. A cursor minted for another
//! search or order is rejected rather than silently returning a different page.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::rbac::RbacErrorCode},
    rbac::model::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE},
};

pub(crate) const RBAC_CURSOR_PURPOSE: &str = "graphql:cursor:rbac";
const RBAC_CURSOR_VERSION: u8 = 1;

pub(crate) const CURSOR_KIND_RESOURCE: u8 = 1;
pub(crate) const CURSOR_KIND_SCOPE: u8 = 2;
pub(crate) const CURSOR_KIND_ROLE: u8 = 3;
pub(crate) const CURSOR_KIND_BINDING: u8 = 5;
pub(crate) const CURSOR_KIND_EFFECTIVE: u8 = 6;
pub(crate) const CURSOR_KIND_CLIENT_TARGET: u8 = 7;
pub(crate) const CURSOR_KIND_CLIENT_SCOPE: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbacTie {
    Id(i64),
    Oid(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbacSortKey {
    CreatedAt {
        created_at: DateTime<Utc>,
        tie: RbacTie,
    },
    Text {
        value: String,
        tie: RbacTie,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacPageDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedPage {
    pub filter_fingerprint: String,
    pub direction: RbacPageDirection,
    pub after: Option<RbacSortKey>,
    pub before: Option<RbacSortKey>,
    pub limit: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    v: u8,
    kind: u8,
    order: u8,
    filter: String,
    created_at_micros: Option<i64>,
    text: Option<String>,
    tie_id: Option<i64>,
    tie_oid: Option<String>,
}

#[must_use]
pub(crate) fn filter_fingerprint<T: Serialize>(kind: u8, order: u8, filter: &T) -> String {
    let encoded = serde_json::to_vec(&(kind, order, filter)).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    let mut value = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn tie_payload(tie: &RbacTie) -> (Option<i64>, Option<String>) {
    match tie {
        RbacTie::Id(id) => (Some(*id), None),
        RbacTie::Oid(oid) => (None, Some(oid.to_string())),
    }
}

pub(crate) async fn encode_cursor(
    protector: &dyn DataProtector,
    kind: u8,
    order: u8,
    filter: &str,
    sort_key: &RbacSortKey,
) -> Result<String, AppError> {
    let (created_at_micros, text, tie_id, tie_oid) = match sort_key {
        RbacSortKey::CreatedAt { created_at, tie } => {
            let (tie_id, tie_oid) = tie_payload(tie);
            (Some(created_at.timestamp_micros()), None, tie_id, tie_oid)
        }
        RbacSortKey::Text { value, tie } => {
            let (tie_id, tie_oid) = tie_payload(tie);
            (None, Some(value.clone()), tie_id, tie_oid)
        }
    };
    let payload = CursorPayload {
        v: RBAC_CURSOR_VERSION,
        kind,
        order,
        filter: filter.to_owned(),
        created_at_micros,
        text,
        tie_id,
        tie_oid,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| AppError::from_code(RbacErrorCode::InvalidCursor).with_source(error))?;
    protector
        .protect(RBAC_CURSOR_PURPOSE, &bytes)
        .await
        .map_err(|error| AppError::from_code(RbacErrorCode::InvalidCursor).with_source(error))
}

pub(crate) async fn decode_cursor(
    protector: &dyn DataProtector,
    kind: u8,
    order: u8,
    filter: &str,
    token: &str,
) -> Result<RbacSortKey, AppError> {
    let invalid = || AppError::from_code(RbacErrorCode::InvalidCursor);
    let bytes = protector
        .unprotect(RBAC_CURSOR_PURPOSE, token)
        .await
        .map_err(|error| invalid().with_source(error))?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|error| invalid().with_source(error))?;
    if payload.v != RBAC_CURSOR_VERSION
        || payload.kind != kind
        || payload.order != order
        || payload.filter != filter
    {
        return Err(invalid());
    }
    let tie = match (payload.tie_id, payload.tie_oid) {
        (Some(id), None) => RbacTie::Id(id),
        (None, Some(oid)) => RbacTie::Oid(Uuid::parse_str(&oid).map_err(|_| invalid())?),
        _ => return Err(invalid()),
    };
    match (payload.created_at_micros, payload.text) {
        (Some(micros), None) => {
            let created_at = DateTime::<Utc>::from_timestamp_micros(micros).ok_or_else(invalid)?;
            Ok(RbacSortKey::CreatedAt { created_at, tie })
        }
        (None, Some(value)) => Ok(RbacSortKey::Text { value, tie }),
        _ => Err(invalid()),
    }
}

pub(crate) async fn prepare_page<T: Serialize>(
    protector: &dyn DataProtector,
    kind: u8,
    order: u8,
    filter: &T,
    first: Option<u32>,
    after: Option<String>,
    last: Option<u32>,
    before: Option<String>,
) -> Result<PreparedPage, AppError> {
    if first.is_some() && last.is_some() {
        return Err(page_conflict());
    }
    if after.is_some() && before.is_some() {
        return Err(page_conflict());
    }
    if first.is_some() && before.is_some() {
        return Err(page_conflict());
    }
    if last.is_some() && after.is_some() {
        return Err(page_conflict());
    }

    let backward = last.is_some() || (first.is_none() && before.is_some());
    let limit = match (first, last) {
        (Some(first), None) => validate_page_size(first, "first")?,
        (None, Some(last)) => validate_page_size(last, "last")?,
        (None, None) => DEFAULT_PAGE_SIZE as usize,
        (Some(_), Some(_)) => return Err(page_conflict()),
    };
    let direction = if backward {
        RbacPageDirection::Backward
    } else {
        RbacPageDirection::Forward
    };
    let fingerprint = filter_fingerprint(kind, order, filter);
    let after = match (direction, after.as_deref()) {
        (RbacPageDirection::Forward, Some(token)) => {
            Some(decode_cursor(protector, kind, order, &fingerprint, token).await?)
        }
        _ => None,
    };
    let before = match (direction, before.as_deref()) {
        (RbacPageDirection::Backward, Some(token)) => {
            Some(decode_cursor(protector, kind, order, &fingerprint, token).await?)
        }
        _ => None,
    };
    Ok(PreparedPage {
        filter_fingerprint: fingerprint,
        direction,
        after,
        before,
        limit,
    })
}

fn page_conflict() -> AppError {
    AppError::from_code(RbacErrorCode::PageArgumentsConflict)
}

fn validate_page_size(value: u32, field: &'static str) -> Result<usize, AppError> {
    if !(1..=MAX_PAGE_SIZE).contains(&value) {
        return Err(AppError::from_code(RbacErrorCode::PageSizeInvalid)
            .with_param("max", MAX_PAGE_SIZE.to_string())
            .with_field(field));
    }
    Ok(value as usize)
}
