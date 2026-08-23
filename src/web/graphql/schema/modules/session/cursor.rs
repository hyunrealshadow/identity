use chrono::{DateTime, TimeZone as _, Utc};
use identity_infrastructure::{
    database::repository::session::SessionSortKey,
    graphql::cursor::{CursorPayload, InvalidCursor},
};

const VERSION: u8 = 2;
const PLAINTEXT_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionCursor {
    last_active_micros: i64,
    id: i64,
}

impl SessionCursor {
    pub(super) fn new(last_active_at: DateTime<Utc>, id: i64) -> Self {
        Self {
            last_active_micros: last_active_at.timestamp_micros(),
            id,
        }
    }

    pub(super) fn into_sort_key(self) -> SessionSortKey {
        SessionSortKey {
            last_active_at: Utc
                .timestamp_micros(self.last_active_micros)
                .single()
                .expect("validated session cursor timestamp"),
            id: self.id,
        }
    }
}

impl CursorPayload for SessionCursor {
    const PURPOSE: &'static str = "graphql:cursor:session";

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PLAINTEXT_SIZE);
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.last_active_micros.to_be_bytes());
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, InvalidCursor> {
        if bytes.len() != PLAINTEXT_SIZE || bytes[0] != VERSION {
            return Err(InvalidCursor);
        }
        let cursor = Self {
            last_active_micros: i64::from_be_bytes(bytes[1..9].try_into().unwrap()),
            id: i64::from_be_bytes(bytes[9..17].try_into().unwrap()),
        };
        if cursor.id <= 0
            || Utc
                .timestamp_micros(cursor.last_active_micros)
                .single()
                .is_none()
        {
            return Err(InvalidCursor);
        }
        Ok(cursor)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use super::SessionCursor;
    use identity_infrastructure::graphql::cursor::CursorPayload as _;

    #[test]
    fn payload_round_trips_the_database_sort_key() {
        let cursor = SessionCursor::new(
            Utc.timestamp_micros(1_800_000_000_123_456).unwrap(),
            9_223_372_036_854,
        );

        assert_eq!(SessionCursor::decode(&cursor.encode()), Ok(cursor));
        assert_eq!(cursor.encode().len(), 17);
    }

    #[test]
    fn payload_rejects_non_positive_database_ids() {
        let cursor = SessionCursor::new(Utc::now(), 0);

        assert!(SessionCursor::decode(&cursor.encode()).is_err());
    }
}
