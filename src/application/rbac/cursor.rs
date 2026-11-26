//! Bounded, filter-bound keyset cursors for every RBAC management list.
//!
//! The cursor is protected by the existing [`DataProtector`] port and carries a
//! digest of the normalized filter plus the order. A cursor minted for another
//! search or order is rejected rather than silently returning a different page.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::rbac},
    pagination::{
        CursorCodecError, PaginationError, RawPageArgs, cursor_fingerprint, protect_json_cursors,
        unprotect_json_cursor, validate_page_arguments,
    },
    rbac::model::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE},
};

pub(crate) const RBAC_CURSOR_PURPOSE: &str = "cursor:rbac";
const RBAC_CURSOR_VERSION: u8 = 1;

pub(crate) const CURSOR_KIND_RESOURCE: u8 = 1;
pub(crate) const CURSOR_KIND_SCOPE: u8 = 2;
pub(crate) const CURSOR_KIND_ROLE: u8 = 3;
pub(crate) const CURSOR_KIND_USER_ROLE: u8 = 5;
pub(crate) const CURSOR_KIND_EFFECTIVE: u8 = 6;
pub(crate) const CURSOR_KIND_CLIENT_SCOPE: u8 = 8;
pub(crate) const CURSOR_KIND_CLIENT: u8 = 9;
/// A single user's direct and inherited roles; ties on the binding OID.
pub(crate) const CURSOR_KIND_USER_ROLE_GRANT: u8 = 12;
pub(crate) const CURSOR_KIND_ACCOUNT_GROUP: u8 = 13;
pub(crate) const CURSOR_KIND_ACCOUNT_ROLE: u8 = 14;
pub(crate) const CURSOR_KIND_ACCOUNT_PERMISSION: u8 = 15;

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

pub type RbacPageDirection = crate::pagination::PageDirection;

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
    cursor_fingerprint(&(kind, order, filter)).unwrap_or_default()
}

fn tie_payload(tie: &RbacTie) -> (Option<i64>, Option<String>) {
    match tie {
        RbacTie::Id(id) => (Some(*id), None),
        RbacTie::Oid(oid) => (None, Some(oid.to_string())),
    }
}

fn build_payload(kind: u8, order: u8, filter: &str, sort_key: &RbacSortKey) -> CursorPayload {
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
    CursorPayload {
        v: RBAC_CURSOR_VERSION,
        kind,
        order,
        filter: filter.to_owned(),
        created_at_micros,
        text,
        tie_id,
        tie_oid,
    }
}

fn map_cursor_codec_error(error: CursorCodecError) -> AppError {
    match error {
        CursorCodecError::EmptyToken => rbac::error::InvalidCursor.into_error(),
        CursorCodecError::Serialize(source) | CursorCodecError::Deserialize(source) => {
            rbac::error::InvalidCursor.into_error().with_source(source)
        }
        CursorCodecError::Protect(source) | CursorCodecError::Unprotect(source) => {
            rbac::error::InvalidCursor.into_error().with_source(source)
        }
    }
}

pub(crate) async fn encode_cursors(
    protector: &dyn DataProtector,
    kind: u8,
    order: u8,
    filter: &str,
    sort_keys: &[&RbacSortKey],
) -> Result<Vec<String>, AppError> {
    let payloads = sort_keys
        .iter()
        .map(|sort_key| build_payload(kind, order, filter, sort_key))
        .collect::<Vec<_>>();
    protect_json_cursors(protector, RBAC_CURSOR_PURPOSE, &payloads)
        .await
        .map_err(map_cursor_codec_error)
}

pub(crate) async fn decode_cursor(
    protector: &dyn DataProtector,
    kind: u8,
    order: u8,
    filter: &str,
    token: &str,
) -> Result<RbacSortKey, AppError> {
    let invalid = || rbac::error::InvalidCursor.into_error();
    let payload: CursorPayload = unprotect_json_cursor(protector, RBAC_CURSOR_PURPOSE, token)
        .await
        .map_err(map_cursor_codec_error)?;
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

/// Relay pagination arguments exactly as the caller supplied them.
pub(crate) struct PageArguments {
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

pub(crate) async fn prepare_page<T: Serialize>(
    protector: &dyn DataProtector,
    kind: u8,
    order: u8,
    filter: &T,
    page: PageArguments,
) -> Result<PreparedPage, AppError> {
    let validated = validate_page_arguments(
        RawPageArgs::from_u32(
            page.first,
            page.after.as_deref(),
            page.last,
            page.before.as_deref(),
        ),
        DEFAULT_PAGE_SIZE as usize,
        MAX_PAGE_SIZE as usize,
    )
    .map_err(|error| match error {
        PaginationError::ConflictingArguments { .. } => {
            rbac::error::PageArgumentsConflict.into_error()
        }
        PaginationError::InvalidPageSize { field, max } => {
            rbac::error::PageSizeInvalid::new(max).with_field(field)
        }
    })?;
    let fingerprint = filter_fingerprint(kind, order, filter);
    let after = match validated.after {
        Some(token) => Some(decode_cursor(protector, kind, order, &fingerprint, token).await?),
        None => None,
    };
    let before = match validated.before {
        Some(token) => Some(decode_cursor(protector, kind, order, &fingerprint, token).await?),
        None => None,
    };
    Ok(PreparedPage {
        filter_fingerprint: fingerprint,
        direction: validated.direction,
        after,
        before,
        limit: validated.limit,
    })
}
