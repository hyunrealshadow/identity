use apalis::prelude::{BoxDynError, Data, TaskBuilder, TaskSink, WorkerBuilder};
use apalis_cron::{CronScheduler, Tick};
use apalis_postgres::{Config, Error, PostgresStorage};
use identity_application::observability::{BusinessEvent, EventValue, event_sink};
use sea_orm::sqlx::PgPool;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use super::{already_queued, period_key, schedule, spawn_until_shutdown};
use crate::state::AppState;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RotationJob;

pub(super) const ROTATION_QUEUE: &str = "identity.credential_rotation";
const ROTATION_PERIOD_SECONDS: u64 = 3_600;

/// Queue the rotation run of the hour containing `timestamp_seconds`, once
/// across all instances.
async fn enqueue_rotation(
    storage: &mut PostgresStorage<RotationJob>,
    timestamp_seconds: u64,
) -> Result<(), BoxDynError> {
    let task = TaskBuilder::new(RotationJob)
        .idempotency_key(period_key(
            ROTATION_QUEUE,
            timestamp_seconds,
            ROTATION_PERIOD_SECONDS,
        ))
        .build();
    match storage.push_task(task).await {
        Ok(()) => Ok(()),
        Err(error) if already_queued(&error) => Ok(()),
        Err(error) => Err(Box::new(error)),
    }
}

async fn maintain_rotation(state: &AppState) -> Result<(), BoxDynError> {
    let mut first_error: Option<BoxDynError> = None;
    match state.services().key_rotation().maintain().await {
        Ok(rotated) if rotated > 0 => {
            info!(rotated, "keys rotated");
            event_sink().emit(
                BusinessEvent::audit("key.rotated")
                    .outcome("rotated")
                    .attribute(
                        "count",
                        EventValue::Integer(i64::try_from(rotated).unwrap_or(i64::MAX)),
                    ),
            );
        }
        Ok(_) => {}
        Err(error) => {
            error!(error = %error, "key rotation maintenance failed");
            first_error = Some(Box::new(error));
        }
    }
    match state.services().login_runtime().maintain().await {
        Ok(rotated) if rotated > 0 => {
            info!(rotated, "built-in client secrets rotated");
            event_sink().emit(
                BusinessEvent::audit("builtin_client.credential.rotated")
                    .outcome("rotated")
                    .attribute(
                        "count",
                        EventValue::Integer(i64::try_from(rotated).unwrap_or(i64::MAX)),
                    ),
            );
        }
        Ok(_) => {}
        Err(error) => {
            error!(error = %error, "built-in client secret rotation failed");
            if first_error.is_none() {
                first_error = Some(Box::new(error));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn handle_rotation_tick(
    tick: Tick,
    storage: Data<PostgresStorage<RotationJob>>,
) -> Result<(), BoxDynError> {
    let mut storage = (*storage).clone();
    enqueue_rotation(&mut storage, tick.get_timestamp())
        .await
        .inspect_err(|error| error!(error = %error, "failed to enqueue rotation job"))
}

async fn handle_rotation_job(_: RotationJob, state: Data<AppState>) -> Result<(), BoxDynError> {
    maintain_rotation(&state).await
}

pub(super) async fn spawn_rotation_workers(state: AppState, pool: PgPool) -> Result<(), Error> {
    let storage = PostgresStorage::<RotationJob>::new(&pool)
        .with_config(Config::default().queue(ROTATION_QUEUE));
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default();
    if let Err(error) = enqueue_rotation(&mut storage.clone(), now).await {
        error!(error = %error, "failed to enqueue the initial rotation job");
    }

    let worker_storage = storage.clone();
    let worker_state = state.clone();
    spawn_until_shutdown(&state, "credential-rotation", move || {
        WorkerBuilder::new(format!("credential-rotation-{}", Uuid::new_v4()))
            .backend(worker_storage.clone())
            .data(worker_state.clone())
            .build(handle_rotation_job)
            .run()
    });

    spawn_until_shutdown(&state, "credential-rotation-scheduler", move || {
        WorkerBuilder::new(format!("credential-rotation-scheduler-{}", Uuid::new_v4()))
            .backend(CronScheduler::new(schedule("@hourly")))
            .data(storage.clone())
            .build(handle_rotation_tick)
            .run()
    });
    Ok(())
}
