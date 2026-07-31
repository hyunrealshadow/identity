use async_graphql::connection::CursorType;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use uuid::Uuid;

const SESSION_CURSOR_KIND: u8 = 1;
const CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionCursor {
    pub last_active_micros: i64,
    pub created_micros: i64,
    pub oid: Uuid,
}

impl SessionCursor {
    #[must_use]
    pub fn new(last_active_at: DateTime<Utc>, created_at: DateTime<Utc>, oid: Uuid) -> Self {
        Self {
            last_active_micros: last_active_at.timestamp_micros(),
            created_micros: created_at.timestamp_micros(),
            oid,
        }
    }

    #[must_use]
    pub fn encode(self) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(SESSION_CURSOR_KIND);
        bytes.push(CURSOR_VERSION);
        bytes.extend_from_slice(&self.last_active_micros.to_be_bytes());
        bytes.extend_from_slice(&self.created_micros.to_be_bytes());
        bytes.extend_from_slice(self.oid.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(value: &str) -> Result<Self, InvalidCursor> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| InvalidCursor)?;
        if bytes.len() != 34 || bytes[0] != SESSION_CURSOR_KIND || bytes[1] != CURSOR_VERSION {
            return Err(InvalidCursor);
        }
        Ok(Self {
            last_active_micros: i64::from_be_bytes(bytes[2..10].try_into().unwrap()),
            created_micros: i64::from_be_bytes(bytes[10..18].try_into().unwrap()),
            oid: Uuid::from_slice(&bytes[18..]).map_err(|_| InvalidCursor)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCursor;

impl std::fmt::Display for InvalidCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid cursor")
    }
}

impl CursorType for SessionCursor {
    type Error = InvalidCursor;

    fn decode_cursor(value: &str) -> Result<Self, Self::Error> {
        Self::decode(value)
    }

    fn encode_cursor(&self) -> String {
        self.encode()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::SessionCursor;

    #[test]
    fn session_cursor_round_trips_binary_sort_key() {
        let cursor = SessionCursor::new(
            Utc.timestamp_micros(1_800_000_000_123_456).unwrap(),
            Utc.timestamp_micros(1_700_000_000_654_321).unwrap(),
            Uuid::parse_str("019c1234-5678-7abc-9def-0123456789ab").unwrap(),
        );

        assert_eq!(SessionCursor::decode(&cursor.encode()), Ok(cursor));
    }
}
