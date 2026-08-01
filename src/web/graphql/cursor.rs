use async_graphql::connection::CursorType;
use chrono::{DateTime, Utc};

const SESSION_CURSOR_VERSION: u8 = 2;
const SESSION_CURSOR_PLAINTEXT_SIZE: usize = 17;
const MAX_PROTECTED_CURSOR_LENGTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCursor {
    pub last_active_micros: i64,
    pub id: i64,
}

impl SessionCursor {
    #[must_use]
    pub fn new(last_active_at: DateTime<Utc>, id: i64) -> Self {
        Self {
            last_active_micros: last_active_at.timestamp_micros(),
            id,
        }
    }

    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SESSION_CURSOR_PLAINTEXT_SIZE);
        bytes.push(SESSION_CURSOR_VERSION);
        bytes.extend_from_slice(&self.last_active_micros.to_be_bytes());
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidCursor> {
        if bytes.len() != SESSION_CURSOR_PLAINTEXT_SIZE || bytes[0] != SESSION_CURSOR_VERSION {
            return Err(InvalidCursor);
        }
        Ok(Self {
            last_active_micros: i64::from_be_bytes(bytes[1..9].try_into().unwrap()),
            id: i64::from_be_bytes(bytes[9..17].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSessionCursor(String);

impl ProtectedSessionCursor {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CursorType for ProtectedSessionCursor {
    type Error = InvalidCursor;

    fn decode_cursor(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_PROTECTED_CURSOR_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidCursor);
        }
        Ok(Self(value.to_owned()))
    }

    fn encode_cursor(&self) -> String {
        self.0.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCursor;

impl std::fmt::Display for InvalidCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid cursor")
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::connection::CursorType as _;
    use chrono::{TimeZone, Utc};

    use super::{ProtectedSessionCursor, SessionCursor};

    #[test]
    fn session_cursor_plaintext_round_trips_the_database_sort_key() {
        let cursor = SessionCursor::new(
            Utc.timestamp_micros(1_800_000_000_123_456).unwrap(),
            9_223_372_036_854,
        );

        assert_eq!(SessionCursor::from_bytes(&cursor.to_bytes()), Ok(cursor));
        assert_eq!(cursor.to_bytes().len(), 17);
    }

    #[test]
    fn protected_cursor_rejects_non_base64url_input_early() {
        assert!(ProtectedSessionCursor::decode_cursor("not/a/cursor").is_err());
        assert!(ProtectedSessionCursor::decode_cursor("").is_err());
    }
}
