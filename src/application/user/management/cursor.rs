//! Protected keyset cursors bound to the normalized filter and order.
//!
//! The cursor is encrypted/authenticated by the existing [`DataProtector`]
//! port. Its payload also carries a digest of the normalized search, so a
//! cursor minted for another filter or sort order is rejected instead of
//! silently returning a different page.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    data_protection::DataProtector,
    error::{AppError, codes::user_management::UserManagementErrorCode},
    user::management::{
        model::{UserFilter, UserOrder},
        repository::UserSortKey,
    },
};

pub(crate) const USER_CURSOR_PURPOSE: &str = "graphql:cursor:user";
const USER_CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedFilter {
    pub query: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub enabled: Option<bool>,
    pub locked: Option<bool>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

impl From<&NormalizedFilter> for UserFilter {
    fn from(filter: &NormalizedFilter) -> Self {
        Self {
            query: filter.query.clone(),
            username: filter.username.clone(),
            email: filter.email.clone(),
            enabled: filter.enabled,
            locked: filter.locked,
            created_from: filter.created_from,
            created_before: filter.created_before,
        }
    }
}

#[derive(Serialize)]
struct FingerprintPayload<'a> {
    query: &'a Option<String>,
    username: &'a Option<String>,
    email: &'a Option<String>,
    enabled: &'a Option<bool>,
    locked: &'a Option<bool>,
    created_from: &'a Option<DateTime<Utc>>,
    created_before: &'a Option<DateTime<Utc>>,
    order: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    v: u8,
    order: u8,
    filter: String,
    id: i64,
    created_at_micros: Option<i64>,
    name_normalized: Option<String>,
}

#[must_use]
pub(crate) fn filter_fingerprint(filter: &NormalizedFilter, order: UserOrder) -> String {
    let payload = FingerprintPayload {
        query: &filter.query,
        username: &filter.username,
        email: &filter.email,
        enabled: &filter.enabled,
        locked: &filter.locked,
        created_from: &filter.created_from,
        created_before: &filter.created_before,
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
    order: UserOrder,
    sort_key: &UserSortKey,
) -> Result<String, AppError> {
    let payload = match sort_key {
        UserSortKey::CreatedAt { created_at, id } => CursorPayload {
            v: USER_CURSOR_VERSION,
            order: order.as_u8(),
            filter: filter_fingerprint(filter, order),
            id: *id,
            created_at_micros: Some(created_at.timestamp_micros()),
            name_normalized: None,
        },
        UserSortKey::Username {
            name_normalized,
            id,
        } => CursorPayload {
            v: USER_CURSOR_VERSION,
            order: order.as_u8(),
            filter: filter_fingerprint(filter, order),
            id: *id,
            created_at_micros: None,
            name_normalized: Some(name_normalized.clone()),
        },
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| {
        AppError::from_code(UserManagementErrorCode::InvalidCursor).with_source(error)
    })?;
    protector
        .protect(USER_CURSOR_PURPOSE, &bytes)
        .await
        .map_err(|error| {
            AppError::from_code(UserManagementErrorCode::InvalidCursor).with_source(error)
        })
}

pub(crate) async fn decode_cursor(
    protector: &dyn DataProtector,
    filter: &NormalizedFilter,
    order: UserOrder,
    token: &str,
) -> Result<UserSortKey, AppError> {
    let invalid = || AppError::from_code(UserManagementErrorCode::InvalidCursor);
    let bytes = protector
        .unprotect(USER_CURSOR_PURPOSE, token)
        .await
        .map_err(|error| invalid().with_source(error))?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|error| invalid().with_source(error))?;
    if payload.v != USER_CURSOR_VERSION
        || payload.order != order.as_u8()
        || payload.filter != filter_fingerprint(filter, order)
    {
        return Err(invalid());
    }
    match order {
        UserOrder::CreatedAtAsc | UserOrder::CreatedAtDesc => {
            let micros = payload.created_at_micros.ok_or_else(invalid)?;
            let created_at = DateTime::<Utc>::from_timestamp_micros(micros).ok_or_else(invalid)?;
            if payload.name_normalized.is_some() {
                return Err(invalid());
            }
            Ok(UserSortKey::CreatedAt {
                created_at,
                id: payload.id,
            })
        }
        UserOrder::UsernameAsc | UserOrder::UsernameDesc => {
            let name_normalized = payload.name_normalized.ok_or_else(invalid)?;
            if payload.created_at_micros.is_some() {
                return Err(invalid());
            }
            Ok(UserSortKey::Username {
                name_normalized,
                id: payload.id,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::{NormalizedFilter, filter_fingerprint};
    use crate::user::management::{model::UserOrder, repository::UserSortKey};

    fn filter(query: Option<&str>) -> NormalizedFilter {
        NormalizedFilter {
            query: query.map(str::to_owned),
            username: None,
            email: None,
            enabled: None,
            locked: None,
            created_from: None,
            created_before: None,
        }
    }

    #[test]
    fn fingerprint_changes_with_filter_or_order() {
        let first = filter(Some("ada"));
        let second = filter(Some("grace"));
        assert_ne!(
            filter_fingerprint(&first, UserOrder::CreatedAtDesc),
            filter_fingerprint(&second, UserOrder::CreatedAtDesc)
        );
        assert_ne!(
            filter_fingerprint(&first, UserOrder::CreatedAtDesc),
            filter_fingerprint(&first, UserOrder::UsernameAsc)
        );
        assert_eq!(
            filter_fingerprint(&first, UserOrder::CreatedAtDesc),
            filter_fingerprint(&first, UserOrder::CreatedAtDesc)
        );
    }

    #[test]
    fn sort_key_keeps_microsecond_precision() {
        let sort = UserSortKey::CreatedAt {
            created_at: chrono::Utc
                .timestamp_opt(1_700_000_000, 123_456_000)
                .unwrap(),
            id: 7,
        };
        match sort {
            UserSortKey::CreatedAt { created_at, id } => {
                assert_eq!(created_at.timestamp_micros(), 1_700_000_000_123_456);
                assert_eq!(id, 7);
            }
            UserSortKey::Username { .. } => unreachable!(),
        }
    }
}
