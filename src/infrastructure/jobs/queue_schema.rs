//! The job queue's migration history before apalis-postgres 1.0 lived in
//! `public._sqlx_migrations`; from 1.0 the queue keeps everything inside the
//! `apalis` schema. A database first set up by an older release has its
//! history moved once, before the queue's own migrations run, as the
//! apalis-postgres upgrade guide prescribes. A fresh database has nothing to
//! move.

use apalis_postgres::PostgresStorage;
use sea_orm::sqlx::{self, PgPool};
use tracing::info;

/// Serializes the move between instances starting at the same time.
const MOVE_LOCK: i64 = 0x6964_656e_7469_7479;

fn refused(message: &str) -> sqlx::Error {
    sqlx::Error::Protocol(format!("job queue migration history: {message}"))
}

/// Move the pre-1.0 migration history of the job queue into the `apalis`
/// schema and re-stamp its first migration, whose definition changed.
pub(super) async fn adopt_legacy_migration_history(pool: &PgPool) -> Result<(), sqlx::Error> {
    let migrator = PostgresStorage::<()>::migrations();
    let known: Vec<i64> = migrator.iter().map(|migration| migration.version).collect();
    let first = migrator
        .iter()
        .next()
        .ok_or_else(|| refused("the queue has no migrations"))?;

    let mut txn = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MOVE_LOCK)
        .execute(&mut *txn)
        .await?;
    let legacy: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations')::text")
            .fetch_one(&mut *txn)
            .await?;
    if legacy.is_none() {
        return Ok(());
    }
    let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM public._sqlx_migrations")
        .fetch_all(&mut *txn)
        .await?;
    if !versions.contains(&first.version) {
        // Some other tool's history; not the queue's.
        return Ok(());
    }
    if versions.iter().any(|version| !known.contains(version)) {
        return Err(refused(
            "public._sqlx_migrations also holds migrations that are not the job queue's; \
             move the queue's rows to apalis._sqlx_migrations by hand",
        ));
    }
    let schema: Option<String> = sqlx::query_scalar("SELECT to_regnamespace('apalis')::text")
        .fetch_one(&mut *txn)
        .await?;
    let jobs_table: Option<String> = sqlx::query_scalar("SELECT to_regclass('apalis.jobs')::text")
        .fetch_one(&mut *txn)
        .await?;
    if schema.is_none() || jobs_table.is_none() {
        return Err(refused(
            "public._sqlx_migrations has queue history, but the apalis schema or apalis.jobs table is missing",
        ));
    }
    let current: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('apalis._sqlx_migrations')::text")
            .fetch_one(&mut *txn)
            .await?;
    if current.is_some() {
        let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM apalis._sqlx_migrations")
            .fetch_one(&mut *txn)
            .await?;
        if recorded > 0 {
            return Err(refused(
                "both public._sqlx_migrations and apalis._sqlx_migrations hold the queue's history",
            ));
        }
        // Left empty by a start that ran the new migrations first and failed.
        sqlx::query("DROP TABLE apalis._sqlx_migrations")
            .execute(&mut *txn)
            .await?;
    }
    sqlx::query("ALTER TABLE public._sqlx_migrations SET SCHEMA apalis")
        .execute(&mut *txn)
        .await?;
    sqlx::query("UPDATE apalis._sqlx_migrations SET checksum = $1 WHERE version = $2")
        .bind(first.checksum.as_ref())
        .bind(first.version)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;
    info!(
        migrations = versions.len(),
        "moved the job queue migration history into the apalis schema"
    );
    Ok(())
}
