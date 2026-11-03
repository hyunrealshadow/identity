use chrono::{DateTime, FixedOffset, Utc};
use identity_domain::{auth::SessionOid, user::UserOid};
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement};
use uuid::Uuid;

use crate::database::query::advisory_transaction_lock;

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

/// Lock the actual target API-resource rows in deterministic URI order.
///
/// Issuance calls this with the resolved target selection before any
/// credential, user, session, client or parent lock, and before inserting the
/// artifact. Semantic resource writers acquire a conflicting `UPDATE` lock on
/// the same row before permanently withdrawing artifacts, so a withdrawal that
/// starts after this lock waits for the issuance transaction and then sees the
/// newly inserted artifact. Parent/request/relation artifacts are still
/// re-read under their own locks afterwards to observe any withdrawal that
/// committed before this transaction acquired the resource lock.
///
/// A URI that was explicitly selected but no longer exists fails closed. An
/// empty selection is valid and takes no lock; it is the OAuth resource
/// omission case, never a fallback for an unknown target.
pub async fn lock_resource_rows<C: ConnectionTrait>(
    connection: &C,
    resource_uris: &[String],
) -> Result<(), DbErr> {
    let mut uris = resource_uris.iter().map(String::as_str).collect::<Vec<_>>();
    uris.sort_unstable();
    uris.dedup();
    for uri in uris {
        let row = connection
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT 1 AS present FROM resource WHERE uri = $1 AND enabled FOR SHARE",
                [uri.into()],
            ))
            .await?;
        if row.is_none() {
            return Err(DbErr::RecordNotFound(format!(
                "selected resource {uri} not found"
            )));
        }
    }
    Ok(())
}

/// Serializes token issuance and revocation for a session across transactions.
pub async fn lock_session<C: ConnectionTrait>(
    connection: &C,
    oid: SessionOid,
) -> Result<(), DbErr> {
    connection
        .execute(&advisory_transaction_lock(session_lock_id(oid)))
        .await?;
    Ok(())
}

fn session_lock_id(oid: SessionOid) -> i64 {
    let uuid = Uuid::from(oid);
    let bytes: [u8; 8] = uuid.as_bytes()[..8]
        .try_into()
        .expect("UUID always contains eight leading bytes");
    i64::from_be_bytes(bytes) ^ 0x5345_5353_494f_4e00_i64
}

/// Serializes credential-group replacements for one user.
pub async fn lock_user_credentials<C: ConnectionTrait>(
    connection: &C,
    oid: UserOid,
) -> Result<(), DbErr> {
    connection
        .execute(&advisory_transaction_lock(user_credential_lock_id(oid)))
        .await?;
    Ok(())
}

fn user_credential_lock_id(oid: UserOid) -> i64 {
    let uuid = Uuid::from(oid);
    let bytes: [u8; 8] = uuid.as_bytes()[..8]
        .try_into()
        .expect("UUID always contains eight leading bytes");
    i64::from_be_bytes(bytes) ^ 0x5553_4552_4352_4544_i64
}
