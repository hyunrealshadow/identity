use std::{str::FromStr, time::Duration};

use apalis::prelude::{
    BoxDynError, Data, Request, Storage, TaskId, WorkerBuilder, WorkerFactoryFn,
};
use apalis_cron::{CronContext, CronStream, Schedule};
use apalis_sql::{
    Config,
    postgres::PostgresStorage,
    sqlx::{Error, PgPool},
};
use chrono::{DateTime, Utc};
use identity_application::error::ErrorDiagnostics;
use serde::{Deserialize, Serialize};
use tokio::{select, spawn};
use tracing::{error, info};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    database::repository::client_authorization::expire_due_authorizations_batch, state::AppState,
};

#[derive(Debug, Clone, Default)]
struct ExpirationTick;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ExpirationJob;

const EXPIRATION_JOB_ID_SUFFIX: u128 = 0x4155_5448_4558_5052;
const EXPIRATION_JOB_NAMESPACE: &str = "identity.authorization_expiration";
const EXPIRATION_BATCH_SIZE: u64 = 1_000;

fn expiration_task_id(timestamp: DateTime<Utc>) -> TaskId {
    let interval_start_millis = timestamp.timestamp_millis().div_euclid(300_000) * 300_000;
    let interval_start_millis =
        u64::try_from(interval_start_millis).expect("expiration schedule must be after Unix epoch");
    Ulid::from_parts(interval_start_millis, EXPIRATION_JOB_ID_SUFFIX)
        .to_string()
        .parse()
        .expect("generated ULID must be a valid task ID")
}

async fn enqueue_expiration(
    storage: &mut PostgresStorage<ExpirationJob>,
    timestamp: DateTime<Utc>,
) -> Result<(), Error> {
    let mut request = Request::new(ExpirationJob);
    request.parts.task_id = expiration_task_id(timestamp);
    match storage.push_request(request).await {
        Ok(_) => Ok(()),
        Err(Error::Database(error))
            if error.code().as_deref() == Some("23505")
                && error.constraint() == Some("unique_job_id") =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn handle_expiration_tick(
    _: ExpirationTick,
    context: CronContext<Utc>,
    storage: Data<PostgresStorage<ExpirationJob>>,
) -> Result<(), BoxDynError> {
    let mut storage = (*storage).clone();
    enqueue_expiration(&mut storage, *context.get_timestamp())
        .await
        .map_err(|error| Box::new(error) as BoxDynError)
}

async fn handle_expiration_job(_: ExpirationJob, state: Data<AppState>) -> Result<(), BoxDynError> {
    let mut total = 0_u64;
    loop {
        let updated = expire_due_authorizations_batch(state.resources().db())
            .await
            .inspect_err(|error| {
                let diagnostics = ErrorDiagnostics::from_error(error);
                error!(
                    error_cause = %diagnostics.cause,
                    error_operation = diagnostics.operation,
                    stacktrace = diagnostics.backtrace.map(ToString::to_string),
                    completed_rows = total,
                    "authorization expiration batch failed"
                );
            })?;
        total += updated;
        if updated < EXPIRATION_BATCH_SIZE {
            break;
        }
    }
    if total > 0 {
        info!(total, "expired authorizations marked inactive");
    }
    Ok(())
}

pub(super) async fn spawn_expiration_workers(state: AppState, pool: PgPool) -> Result<(), Error> {
    let storage = PostgresStorage::<ExpirationJob>::new_with_config(
        pool,
        Config::new(EXPIRATION_JOB_NAMESPACE).set_poll_interval(Duration::from_secs(30)),
    );
    enqueue_expiration(&mut storage.clone(), Utc::now()).await?;

    let job_state = state.clone();
    let job_storage = storage.clone();
    spawn(async move {
        let mut shutdown = job_state.lifecycle().subscribe_shutdown();
        let worker = WorkerBuilder::new(format!("authorization-expiration-{}", Uuid::new_v4()))
            .data(job_state)
            .backend(job_storage)
            .build_fn(handle_expiration_job);
        select! {
            () = worker.run() => error!("authorization expiration worker stopped"),
            _ = async {
                while shutdown.changed().await.is_ok() && !*shutdown.borrow() {}
            } => {}
        }
    });

    spawn(async move {
        let mut shutdown = state.lifecycle().subscribe_shutdown();
        let schedule =
            Schedule::from_str("0 */5 * * * *").expect("valid five-minute expiration schedule");
        let worker = WorkerBuilder::new("authorization-expiration-scheduler")
            .data(storage)
            .backend(CronStream::new(schedule))
            .build_fn(handle_expiration_tick);
        select! {
            () = worker.run() => error!("authorization expiration scheduler stopped"),
            _ = async {
                while shutdown.changed().await.is_ok() && !*shutdown.borrow() {}
            } => {}
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use apalis_cron::Schedule;
    use chrono::{TimeZone as _, Utc};

    use super::expiration_task_id;

    #[test]
    fn expiration_job_id_is_shared_by_instances_for_one_interval() {
        let first = Utc.with_ymd_and_hms(2026, 9, 29, 10, 0, 0).unwrap();
        let same_interval = Utc.with_ymd_and_hms(2026, 9, 29, 10, 4, 59).unwrap();
        let next_interval = Utc.with_ymd_and_hms(2026, 9, 29, 10, 5, 0).unwrap();

        assert_eq!(expiration_task_id(first), expiration_task_id(same_interval));
        assert_ne!(expiration_task_id(first), expiration_task_id(next_interval));
        assert!(Schedule::from_str("0 */5 * * * *").is_ok());
    }
}
