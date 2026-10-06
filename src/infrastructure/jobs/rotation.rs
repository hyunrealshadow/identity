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
use identity_application::observability::{BusinessEvent, EventValue, event_sink};
use serde::{Deserialize, Serialize};
use tokio::{select, spawn};
use tracing::{error, info};
use ulid::Ulid;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Clone, Default)]
struct RotationTick;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RotationJob;

const ROTATION_JOB_ID_SUFFIX: u128 = 0x524F_5441_5449_4F4E;
const ROTATION_JOB_NAMESPACE: &str = "identity.credential_rotation";

fn rotation_task_id(timestamp: DateTime<Utc>) -> TaskId {
    let hour_start_millis = timestamp.timestamp_millis().div_euclid(3_600_000) * 3_600_000;
    let hour_start_millis =
        u64::try_from(hour_start_millis).expect("rotation schedule must be after Unix epoch");
    Ulid::from_parts(hour_start_millis, ROTATION_JOB_ID_SUFFIX)
        .to_string()
        .parse()
        .expect("generated ULID must be a valid task ID")
}

async fn enqueue_rotation(
    storage: &mut PostgresStorage<RotationJob>,
    timestamp: DateTime<Utc>,
) -> Result<(), Error> {
    let mut request = Request::new(RotationJob);
    request.parts.task_id = rotation_task_id(timestamp);
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
    _: RotationTick,
    context: CronContext<Utc>,
    storage: Data<PostgresStorage<RotationJob>>,
) -> Result<(), BoxDynError> {
    let mut storage = (*storage).clone();
    enqueue_rotation(&mut storage, *context.get_timestamp())
        .await
        .map_err(|error| {
            error!(error = %error, "failed to enqueue rotation job");
            Box::new(error) as BoxDynError
        })
}

async fn handle_rotation_job(_: RotationJob, data: Data<AppState>) -> Result<(), BoxDynError> {
    maintain_rotation(&data).await
}

pub(super) async fn spawn_rotation_workers(state: AppState, pool: PgPool) -> Result<(), Error> {
    let storage = PostgresStorage::<RotationJob>::new_with_config(
        pool,
        Config::new(ROTATION_JOB_NAMESPACE).set_poll_interval(Duration::from_secs(30)),
    );
    enqueue_rotation(&mut storage.clone(), Utc::now()).await?;

    let job_state = state.clone();
    let job_storage = storage.clone();
    spawn(async move {
        let mut shutdown = job_state.lifecycle().subscribe_shutdown();
        let worker = WorkerBuilder::new(format!("credential-rotation-{}", Uuid::new_v4()))
            .data(job_state)
            .backend(job_storage)
            .build_fn(handle_rotation_job);
        select! {
            () = worker.run() => error!("rotation job worker stopped"),
            _ = async {
                while shutdown.changed().await.is_ok() && !*shutdown.borrow() {}
            } => {}
        }
    });

    spawn(async move {
        let mut shutdown = state.lifecycle().subscribe_shutdown();
        let schedule = Schedule::from_str("@hourly").expect("valid rotation schedule");
        let worker = WorkerBuilder::new("credential-rotation-scheduler")
            .data(storage)
            .backend(CronStream::new(schedule))
            .build_fn(handle_rotation_tick);
        select! {
            () = worker.run() => error!("rotation scheduler stopped"),
            _ = async {
                while shutdown.changed().await.is_ok() && !*shutdown.borrow() {}
            } => {}
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use super::rotation_task_id;

    #[test]
    fn rotation_job_id_is_shared_by_instances_for_one_hour() {
        let first = Utc.with_ymd_and_hms(2026, 9, 28, 10, 0, 0).unwrap();
        let same_hour = Utc.with_ymd_and_hms(2026, 9, 28, 10, 59, 59).unwrap();
        let next_hour = Utc.with_ymd_and_hms(2026, 9, 28, 11, 0, 0).unwrap();

        assert_eq!(rotation_task_id(first), rotation_task_id(same_hour));
        assert_ne!(rotation_task_id(first), rotation_task_id(next_hour));
    }
}
