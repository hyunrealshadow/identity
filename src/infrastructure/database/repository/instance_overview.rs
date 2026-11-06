use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::SessionStatus,
    instance_overview::{
        InstanceClientCounts, InstanceDailyCount, InstanceOverviewRepository,
        InstanceOverviewRepositoryError, InstanceResourceCounts, InstanceSessionCounts,
        InstanceUserCounts, NewUserWindow,
    },
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, QueryResult, Statement, TryGetable,
};

pub struct InstanceOverviewRepositoryImpl {
    db: DatabaseConnection,
}

impl InstanceOverviewRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage_error(error: DbErr) -> InstanceOverviewRepositoryError {
    InstanceOverviewRepositoryError::QueryFailed(Box::new(error))
}

fn missing_row() -> InstanceOverviewRepositoryError {
    InstanceOverviewRepositoryError::QueryFailed(Box::new(DbErr::RecordNotFound(
        "instance overview aggregate row is missing".to_owned(),
    )))
}

fn column<T: TryGetable>(
    row: &QueryResult,
    name: &str,
) -> Result<T, InstanceOverviewRepositoryError> {
    row.try_get::<T>("", name)
        .map_err(|error| InstanceOverviewRepositoryError::QueryFailed(Box::new(error)))
}

#[async_trait]
impl InstanceOverviewRepository for InstanceOverviewRepositoryImpl {
    #[tracing::instrument(
        skip_all,
        name = "db.query",
        fields(db.system = "postgresql", db.operation = "instance_overview_users")
    )]
    async fn user_counts(
        &self,
        window: NewUserWindow,
    ) -> Result<InstanceUserCounts, InstanceOverviewRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT COUNT(*)::bigint AS total, \
                 COUNT(*) FILTER (WHERE enabled)::bigint AS enabled \
                 FROM \"user\""
                    .to_owned(),
            ))
            .await
            .map_err(storage_error)?
            .ok_or_else(missing_row)?;
        let total = column::<i64>(&row, "total")?;
        let enabled = column::<i64>(&row, "enabled")?;

        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT (created_at AT TIME ZONE $3::text)::date AS bucket_date, \
                 COUNT(*)::bigint AS bucket_count \
                 FROM \"user\" \
                 WHERE created_at >= $1 AND created_at < $2 \
                 GROUP BY (created_at AT TIME ZONE $3::text)::date \
                 ORDER BY bucket_date ASC",
                [
                    window.start.fixed_offset().into(),
                    window.end.fixed_offset().into(),
                    window.time_zone.name().to_owned().into(),
                ],
            ))
            .await
            .map_err(storage_error)?;
        let registrations = rows
            .iter()
            .map(|row| {
                Ok(InstanceDailyCount {
                    date: column(row, "bucket_date")?,
                    count: column(row, "bucket_count")?,
                })
            })
            .collect::<Result<Vec<_>, InstanceOverviewRepositoryError>>()?;

        Ok(InstanceUserCounts {
            total,
            enabled,
            registrations,
        })
    }

    #[tracing::instrument(
        skip_all,
        name = "db.query",
        fields(db.system = "postgresql", db.operation = "instance_overview_clients")
    )]
    async fn client_counts(&self) -> Result<InstanceClientCounts, InstanceOverviewRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT COUNT(*)::bigint AS total, \
                 COUNT(*) FILTER (WHERE c.built_in)::bigint AS built_in, \
                 COUNT(*) FILTER (WHERE EXISTS ( \
                     SELECT 1 FROM client_openid_connect oidc WHERE oidc.client_id = c.id \
                 ))::bigint AS enabled \
                 FROM client c"
                    .to_owned(),
            ))
            .await
            .map_err(storage_error)?
            .ok_or_else(missing_row)?;
        Ok(InstanceClientCounts {
            total: column(&row, "total")?,
            enabled: column(&row, "enabled")?,
            built_in: column(&row, "built_in")?,
        })
    }

    #[tracing::instrument(
        skip_all,
        name = "db.query",
        fields(db.system = "postgresql", db.operation = "instance_overview_sessions")
    )]
    async fn session_counts(
        &self,
        generated_at: DateTime<Utc>,
    ) -> Result<InstanceSessionCounts, InstanceOverviewRepositoryError> {
        let lower = generated_at - Duration::hours(24);
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT \
                 COUNT(*) FILTER ( \
                     WHERE s.status = $3 \
                       AND s.revoked_at IS NULL \
                       AND s.expires_at > $1 \
                       AND u.enabled = true \
                       AND u.locked = false \
                 )::bigint AS active, \
                 COUNT(*) FILTER ( \
                     WHERE s.created_at >= $2 AND s.created_at <= $1 \
                 )::bigint AS created_last_24_hours \
                 FROM session s \
                 JOIN \"user\" u ON u.id = s.user_id",
                [
                    generated_at.fixed_offset().into(),
                    lower.fixed_offset().into(),
                    SessionStatus::ACTIVE.as_str().into(),
                ],
            ))
            .await
            .map_err(storage_error)?
            .ok_or_else(missing_row)?;
        Ok(InstanceSessionCounts {
            active: column(&row, "active")?,
            created_last_24_hours: column(&row, "created_last_24_hours")?,
        })
    }

    #[tracing::instrument(
        skip_all,
        name = "db.query",
        fields(db.system = "postgresql", db.operation = "instance_overview_resources")
    )]
    async fn resource_counts(
        &self,
    ) -> Result<InstanceResourceCounts, InstanceOverviewRepositoryError> {
        let row = self
            .db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT COUNT(*)::bigint AS total, \
                 COUNT(*) FILTER (WHERE enabled)::bigint AS enabled \
                 FROM resource"
                    .to_owned(),
            ))
            .await
            .map_err(storage_error)?
            .ok_or_else(missing_row)?;
        Ok(InstanceResourceCounts {
            total: column(&row, "total")?,
            enabled: column(&row, "enabled")?,
        })
    }
}
