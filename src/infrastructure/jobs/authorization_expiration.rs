use apalis::prelude::{BoxDynError, Data, TaskBuilder, TaskSink, WorkerBuilder};
use apalis_cron::{CronScheduler, Tick};
use apalis_postgres::{Config, Error, PostgresStorage};
use identity_application::error::ErrorDiagnostics;
use sea_orm::sqlx::PgPool;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use super::{already_queued, period_key, schedule, spawn_until_shutdown};
use crate::{
    database::repository::client_authorization::expire_due_authorizations_batch, state::AppState,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ExpirationJob;

pub(super) const EXPIRATION_QUEUE: &str = "identity.authorization_expiration";
const EXPIRATION_PERIOD_SECONDS: u64 = 300;
const EXPIRATION_BATCH_SIZE: u64 = 1_000;

/// Queue the expiration run of the five minutes containing
/// `timestamp_seconds`, once across all instances.
async fn enqueue_expiration(
    storage: &mut PostgresStorage<ExpirationJob>,
    timestamp_seconds: u64,
) -> Result<(), BoxDynError> {
    let task = TaskBuilder::new(ExpirationJob)
        .idempotency_key(period_key(
            EXPIRATION_QUEUE,
            timestamp_seconds,
            EXPIRATION_PERIOD_SECONDS,
        ))
        .build();
    match storage.push_task(task).await {
        Ok(()) => Ok(()),
        Err(error) if already_queued(&error) => Ok(()),
        Err(error) => Err(Box::new(error)),
    }
}

async fn handle_expiration_tick(
    tick: Tick,
    storage: Data<PostgresStorage<ExpirationJob>>,
) -> Result<(), BoxDynError> {
    let mut storage = (*storage).clone();
    enqueue_expiration(&mut storage, tick.get_timestamp()).await
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
    let storage = PostgresStorage::<ExpirationJob>::new(&pool)
        .with_config(Config::default().queue(EXPIRATION_QUEUE));
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default();
    if let Err(error) = enqueue_expiration(&mut storage.clone(), now).await {
        error!(error = %error, "failed to enqueue the initial authorization expiration job");
    }

    let worker_storage = storage.clone();
    let worker_state = state.clone();
    spawn_until_shutdown(&state, "authorization-expiration", move || {
        WorkerBuilder::new(format!("authorization-expiration-{}", Uuid::new_v4()))
            .backend(worker_storage.clone())
            .data(worker_state.clone())
            .build(handle_expiration_job)
            .run()
    });

    spawn_until_shutdown(&state, "authorization-expiration-scheduler", move || {
        WorkerBuilder::new(format!(
            "authorization-expiration-scheduler-{}",
            Uuid::new_v4()
        ))
        .backend(CronScheduler::new(schedule("0 */5 * * * *")))
        .data(storage.clone())
        .build(handle_expiration_tick)
        .run()
    });
    Ok(())
}
