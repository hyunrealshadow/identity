//! Removes finished jobs, which the queue keeps otherwise. Email jobs go as
//! soon as they finish: a delivered or abandoned message is reported in the
//! logs and events and its protected body has no further use. Maintenance
//! runs stay a day, so a restart within their period still finds the run
//! and does not queue it again. Every instance runs the same delete.

use apalis::prelude::{BoxDynError, Data, WorkerBuilder};
use apalis_cron::{CronScheduler, Tick};
use sea_orm::sqlx::{self, PgPool};
use tracing::{debug, error};
use uuid::Uuid;

use super::{BackgroundWorkers, schedule, spawn_until_shutdown};
use crate::{email::EMAIL_QUEUE, state::AppState};

/// The queues whose finished runs are kept for a day.
const MAINTENANCE_QUEUES: [&str; 2] = [
    super::rotation::ROTATION_QUEUE,
    super::authorization_expiration::EXPIRATION_QUEUE,
];

async fn purge(_: Tick, pool: Data<PgPool>) -> Result<(), BoxDynError> {
    let maintenance: Vec<String> = MAINTENANCE_QUEUES
        .iter()
        .map(|&queue| queue.to_owned())
        .collect();
    let removed = sqlx::query(
        "DELETE FROM apalis.jobs \
         WHERE (status IN ('Done', 'Killed') OR (status = 'Failed' AND attempts >= max_attempts)) \
           AND ((job_type = $1) OR (job_type = ANY($2) AND COALESCE(done_at, run_at) < now() - interval '1 day'))",
    )
    .bind(EMAIL_QUEUE)
    .bind(&maintenance)
    .execute(&*pool)
    .await
    .inspect_err(|error| error!(error = %error, "finished jobs could not be removed"))?
    .rows_affected();
    let pruned_workers = sqlx::query(
        "DELETE FROM apalis.workers AS worker \
         WHERE worker.last_seen < now() - interval '1 day' \
           AND NOT EXISTS (SELECT 1 FROM apalis.jobs AS job WHERE job.lock_by = worker.id)",
    )
    .execute(&*pool)
    .await
    .inspect_err(|error| error!(error = %error, "stale worker rows could not be removed"))?
    .rows_affected();
    debug!(removed, pruned_workers, "finished jobs removed");
    Ok(())
}

pub(super) fn spawn_cleanup_worker(
    state: &AppState,
    pool: &PgPool,
    workers: &mut BackgroundWorkers,
) {
    let pool = pool.clone();
    spawn_until_shutdown(state, workers, "job-cleanup", move |signal| {
        WorkerBuilder::new(format!("job-cleanup-{}", Uuid::new_v4()))
            .backend(CronScheduler::new(schedule("0 */5 * * * *")))
            .data(pool.clone())
            .build(purge)
            .run_until(signal)
    });
}
