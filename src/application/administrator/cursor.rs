//! Signed, filter-bound keyset cursors for the administrator directory.
//!
//! The cursor is protected by the existing [`DataProtector`] port. Its payload
//! carries a digest of the normalized filter plus the requested order, so a
//! cursor minted for another search or order is rejected instead of silently
//! returning a different page.

use identity_domain::{authorization::AdministratorRole, user::UserOid};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::administrator::AdministratorErrorCode},
};

use super::{
    model::{AdministratorFilter, AdministratorOrder, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE},
    repository::{AdministratorPageDirection, AdministratorSortKey},
};

pub(crate) const ADMINISTRATOR_CURSOR_PURPOSE: &str = "graphql:cursor:administrator";
const ADMINISTRATOR_CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedFilter {
    pub query: Option<String>,
    pub role: Option<AdministratorRole>,
    pub enabled: Option<bool>,
    pub user_oid: Option<UserOid>,
}

impl From<&NormalizedFilter> for AdministratorFilter {
    fn from(filter: &NormalizedFilter) -> Self {
        Self {
            query: filter.query.clone(),
            role: filter.role,
            enabled: filter.enabled,
            user_oid: filter.user_oid,
        }
    }
}

#[derive(Serialize)]
struct FingerprintPayload<'a> {
    query: &'a Option<String>,
    role: &'a Option<&'static str>,
    enabled: &'a Option<bool>,
    user_oid: &'a Option<Uuid>,
    order: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    v: u8,
    order: u8,
    filter: String,
    id: i64,
    created_at_micros: Option<i64>,
}

#[must_use]
pub(crate) fn filter_fingerprint(filter: &NormalizedFilter, order: AdministratorOrder) -> String {
    let role = filter.role.map(AdministratorRole::as_str);
    let user_oid = filter.user_oid.map(|oid| oid.0);
    let payload = FingerprintPayload {
        query: &filter.query,
        role: &role,
        enabled: &filter.enabled,
        user_oid: &user_oid,
        order: order.as_u8(),
    };
    let encoded = serde_json::to_vec(&payload).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    let mut value = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub(crate) async fn encode_cursor(
    protector: &dyn DataProtector,
    filter: &NormalizedFilter,
    order: AdministratorOrder,
    sort_key: &AdministratorSortKey,
) -> Result<String, AppError> {
    let AdministratorSortKey::CreatedAt { created_at, id } = sort_key;
    let payload = CursorPayload {
        v: ADMINISTRATOR_CURSOR_VERSION,
        order: order.as_u8(),
        filter: filter_fingerprint(filter, order),
        id: *id,
        created_at_micros: Some(created_at.timestamp_micros()),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| {
        AppError::from_code(AdministratorErrorCode::InvalidCursor).with_source(error)
    })?;
    protector
        .protect(ADMINISTRATOR_CURSOR_PURPOSE, &bytes)
        .await
        .map_err(|error| {
            AppError::from_code(AdministratorErrorCode::InvalidCursor).with_source(error)
        })
}

pub(crate) async fn decode_cursor(
    protector: &dyn DataProtector,
    filter: &NormalizedFilter,
    order: AdministratorOrder,
    token: &str,
) -> Result<AdministratorSortKey, AppError> {
    let invalid = || AppError::from_code(AdministratorErrorCode::InvalidCursor);
    let bytes = protector
        .unprotect(ADMINISTRATOR_CURSOR_PURPOSE, token)
        .await
        .map_err(|error| invalid().with_source(error))?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|error| invalid().with_source(error))?;
    if payload.v != ADMINISTRATOR_CURSOR_VERSION
        || payload.order != order.as_u8()
        || payload.filter != filter_fingerprint(filter, order)
    {
        return Err(invalid());
    }
    let micros = payload.created_at_micros.ok_or_else(invalid)?;
    let created_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp_micros(micros).ok_or_else(invalid)?;
    Ok(AdministratorSortKey::CreatedAt {
        created_at,
        id: payload.id,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedPage {
    pub direction: AdministratorPageDirection,
    pub after: Option<AdministratorSortKey>,
    pub before: Option<AdministratorSortKey>,
    pub limit: usize,
}

pub(crate) async fn prepare_page(
    protector: &dyn DataProtector,
    filter: &NormalizedFilter,
    order: AdministratorOrder,
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
        AdministratorPageDirection::Backward
    } else {
        AdministratorPageDirection::Forward
    };
    let after = match (direction, after.as_deref()) {
        (AdministratorPageDirection::Forward, Some(token)) => {
            Some(decode_cursor(protector, filter, order, token).await?)
        }
        _ => None,
    };
    let before = match (direction, before.as_deref()) {
        (AdministratorPageDirection::Backward, Some(token)) => {
            Some(decode_cursor(protector, filter, order, token).await?)
        }
        _ => None,
    };
    Ok(PreparedPage {
        direction,
        after,
        before,
        limit,
    })
}

fn page_conflict() -> AppError {
    AppError::from_code(AdministratorErrorCode::PageArgumentsConflict)
}

fn validate_page_size(value: u32, field: &'static str) -> Result<usize, AppError> {
    if !(1..=MAX_PAGE_SIZE).contains(&value) {
        return Err(AppError::from_code(AdministratorErrorCode::PageSizeInvalid)
            .with_param("max", MAX_PAGE_SIZE.to_string())
            .with_field(field));
    }
    Ok(value as usize)
}

#[cfg(test)]
mod tests {
    use identity_domain::authorization::AdministratorRole;

    use super::{NormalizedFilter, filter_fingerprint};
    use crate::administrator::model::AdministratorOrder;

    fn filter(query: Option<&str>, role: Option<AdministratorRole>) -> NormalizedFilter {
        NormalizedFilter {
            query: query.map(str::to_owned),
            role,
            enabled: None,
            user_oid: None,
        }
    }

    #[test]
    fn fingerprint_changes_with_filter_or_order() {
        let first = filter(Some("ada"), None);
        let second = filter(Some("grace"), None);
        assert_ne!(
            filter_fingerprint(&first, AdministratorOrder::CreatedAtDesc),
            filter_fingerprint(&second, AdministratorOrder::CreatedAtDesc)
        );
        assert_ne!(
            filter_fingerprint(&first, AdministratorOrder::CreatedAtDesc),
            filter_fingerprint(&first, AdministratorOrder::CreatedAtAsc)
        );
        assert_ne!(
            filter_fingerprint(&first, AdministratorOrder::CreatedAtDesc),
            filter_fingerprint(
                &filter(Some("ada"), Some(AdministratorRole::Admin)),
                AdministratorOrder::CreatedAtDesc
            )
        );
    }
}
