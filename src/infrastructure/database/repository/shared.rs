use chrono::{DateTime, FixedOffset, Utc};

/// Sentinel value used to represent "no expiry" in the database,
/// since nullable timestamp columns would require schema changes.
pub(super) fn non_expiring_timestamp() -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339("9999-12-31T23:59:59+00:00")
        .expect("non-expiring timestamp literal should be valid")
}

/// Convert a database timestamp to `Option<DateTime<Utc>>`,
/// mapping the sentinel value to `None`.
pub(super) fn decode_optional_expiry(value: DateTime<FixedOffset>) -> Option<DateTime<Utc>> {
    if value == non_expiring_timestamp() {
        None
    } else {
        Some(value.with_timezone(&Utc))
    }
}

/// Convert `Option<DateTime<Utc>>` to a database timestamp,
/// encoding `None` as the sentinel "never expires" value.
pub(super) fn encode_optional_expiry(value: Option<DateTime<Utc>>) -> DateTime<FixedOffset> {
    value.map(Into::into).unwrap_or_else(non_expiring_timestamp)
}
