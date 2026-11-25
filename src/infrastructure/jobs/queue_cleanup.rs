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

use super::{schedule, spawn_until_shutdown};
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
           AND ((job_type = $1) OR (job_type = ANY($2) AND done_at < now() - interval '1 day'))",
    )
    .bind(EMAIL_QUEUE)
    .bind(&maintenance)
    .execute(&*pool)
    .await
    .inspect_err(|error| error!(error = %error, "finished jobs could not be removed"))?
    .rows_affected();
    debug!(removed, "finished jobs removed");
    Ok(())
}

pub(super) fn spawn_cleanup_worker(state: &AppState, pool: &PgPool) {
    let pool = pool.clone();
    spawn_until_shutdown(state, "job-cleanup", move || {
        WorkerBuilder::new(format!("job-cleanup-{}", Uuid::new_v4()))
            .backend(CronScheduler::new(schedule("0 */5 * * * *")))
            .data(pool.clone())
            .build(purge)
            .run()
    });
}
