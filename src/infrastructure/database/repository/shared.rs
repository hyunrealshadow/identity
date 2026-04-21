use chrono::{DateTime, FixedOffset, Utc};

/// Sentinel value used to represent "no expiry" in the database,
/// since nullable timestamp columns would require schema changes.
pub fn non_expiring_timestamp() -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339("9999-12-31T23:59:59+00:00")
        .expect("non-expiring timestamp literal should be valid")
}

/// Convert a nullable database timestamp to `Option<DateTime<Utc>>`.
/// Used for columns that are actually nullable in the database schema.
pub fn decode_nullable_expiry(value: Option<DateTime<FixedOffset>>) -> Option<DateTime<Utc>> {
    value.map(|v| v.with_timezone(&Utc))
}

/// Convert `Option<DateTime<Utc>>` to a nullable database timestamp.
/// Used for columns that are actually nullable in the database schema.
pub fn encode_nullable_expiry(value: Option<DateTime<Utc>>) -> Option<DateTime<FixedOffset>> {
    value.map(Into::into)
}

/// Convert a non-nullable database timestamp to `Option<DateTime<Utc>>`,
/// mapping the sentinel value to `None`.
/// Used for columns that are NOT nullable in the database schema
/// but represent optional expiry in the domain model.
pub fn decode_nonnullable_expiry(value: DateTime<FixedOffset>) -> Option<DateTime<Utc>> {
    if value == non_expiring_timestamp() {
        None
    } else {
        Some(value.with_timezone(&Utc))
    }
}

/// Convert `Option<DateTime<Utc>>` to a non-nullable database timestamp,
/// encoding `None` as the sentinel "never expires" value.
/// Used for columns that are NOT nullable in the database schema
/// but represent optional expiry in the domain model.
pub fn encode_nonnullable_expiry(value: Option<DateTime<Utc>>) -> DateTime<FixedOffset> {
    value.map(Into::into).unwrap_or_else(non_expiring_timestamp)
}
