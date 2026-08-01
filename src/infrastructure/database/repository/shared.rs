use chrono::{DateTime, FixedOffset, Utc};
use identity_domain::auth::SessionOid;
use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};

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

/// Serializes token issuance and revocation for a session across transactions.
pub async fn lock_session<C: ConnectionTrait>(
    connection: &C,
    oid: SessionOid,
) -> Result<(), DbErr> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock($1)",
            [session_lock_id(oid).into()],
        ))
        .await?;
    Ok(())
}

fn session_lock_id(oid: SessionOid) -> i64 {
    let uuid = uuid::Uuid::from(oid);
    let bytes: [u8; 8] = uuid.as_bytes()[..8]
        .try_into()
        .expect("UUID always contains eight leading bytes");
    i64::from_be_bytes(bytes) ^ 0x5345_5353_494f_4e00_i64
}

#[cfg(test)]
mod tests {
    use super::session_lock_id;
    use identity_domain::auth::SessionOid;
    use uuid::Uuid;

    #[test]
    fn session_lock_id_is_stable_and_session_specific() {
        let first = SessionOid(Uuid::parse_str("019c1234-5678-7abc-9def-0123456789ab").unwrap());
        let second = SessionOid(Uuid::parse_str("019c1234-5678-7abd-9def-0123456789ab").unwrap());

        assert_eq!(session_lock_id(first), session_lock_id(first));
        assert_ne!(session_lock_id(first), session_lock_id(second));
    }
}
