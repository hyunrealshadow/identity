use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    time::{Duration, Instant},
};

use apalis::prelude::{TaskSinkError, WorkerError};
use apalis_postgres::{Error, PostgresStorage};
use sea_orm::sqlx::{self, postgres::PgPoolOptions};
use tokio::{select, sync::watch, task::JoinSet};
use tracing::{error, warn};

use crate::{config::AppConfig, state::AppState};

pub mod authorization_expiration;
mod email;
mod queue_cleanup;
mod queue_schema;
pub mod rotation;

pub type ShutdownSignal = Pin<Box<dyn Future<Output = Result<(), WorkerError>> + Send>>;

/// Running background workers managed until application shutdown.
pub struct BackgroundWorkers {
    tasks: JoinSet<()>,
}

impl BackgroundWorkers {
    /// Wait for background workers to drain in-flight work until `timeout`.
    pub async fn shutdown(mut self, timeout: Duration) {
        if tokio::time::timeout(timeout, async {
            while let Some(result) = self.tasks.join_next().await {
                if let Err(error) = result
                    && error.is_panic()
                {
                    error!(error = %error, "background worker panicked during shutdown");
                }
            }
        })
        .await
        .is_err()
        {
            warn!(
                remaining = self.tasks.len(),
                timeout_seconds = timeout.as_secs(),
                "background workers did not finish before shutdown timeout"
            );
            self.tasks.abort_all();
        }
    }
}

pub async fn spawn_background_workers(
    state: AppState,
    config: &AppConfig,
) -> Result<BackgroundWorkers, Error> {
    // The workers poll and send heartbeats on a small pool of their own, so
    // they neither wait for nor hold up request handling. Email is queued on
    // the connection of the transaction that causes it.
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_millis(config.database.connect_timeout))
        .connect(&config.database.uri)
        .await?;
    if config.database.auto_migrate {
        prepare_queue(&pool).await?;
    }

    let mut workers = BackgroundWorkers {
        tasks: JoinSet::new(),
    };
    rotation::spawn_rotation_workers(state.clone(), pool.clone(), &mut workers).await?;
    authorization_expiration::spawn_expiration_workers(state.clone(), pool.clone(), &mut workers)
        .await?;
    email::spawn_email_workers(&state, &pool, &mut workers);
    queue_cleanup::spawn_cleanup_worker(&state, &pool, &mut workers);
    Ok(workers)
}

/// Create or upgrade the job queue's tables in the `apalis` schema.
pub async fn prepare_queue(pool: &sqlx::PgPool) -> Result<(), Error> {
    queue_schema::adopt_legacy_migration_history(pool).await?;
    PostgresStorage::<()>::setup(pool).await
}

/// The idempotency key of a maintenance run: every instance computes the
/// same key for one period, so the run is queued once whichever instance's
/// scheduler fires first.
fn period_key(prefix: &str, timestamp_seconds: u64, period_seconds: u64) -> String {
    format!(
        "{prefix}:{}",
        timestamp_seconds - timestamp_seconds % period_seconds
    )
}

/// Whether a push failed only because the run of this period is queued
/// already.
fn already_queued(error: &TaskSinkError<Error>) -> bool {
    matches!(
        error,
        TaskSinkError::PushError(Error::Database(sqlx::Error::Database(error)))
            if error.code().as_deref() == Some("23505")
    )
}

/// The cron schedule `expression`, which is fixed in code.
fn schedule(expression: &str) -> cron::Schedule {
    cron::Schedule::from_str(expression).expect("valid maintenance schedule")
}

/// Delay before a stopped worker is started again; it doubles up to the
/// maximum while the worker keeps failing soon after it starts.
const RESTART_DELAY: Duration = Duration::from_secs(1);
const MAX_RESTART_DELAY: Duration = Duration::from_secs(60);
/// A worker that ran at least this long starts over at the shortest delay.
const STABLE_RUN: Duration = Duration::from_secs(300);

fn shutdown_signal(mut shutdown: watch::Receiver<bool>) -> ShutdownSignal {
    Box::pin(async move {
        let _ = shutdown.wait_for(|&stopped| stopped).await;
        Ok(())
    })
}

/// Keep a worker running until the application shuts down. A worker stops
/// when its backend fails, for example when no database connection is free
/// in time; it is started again, under a new name, after a delay.
fn spawn_until_shutdown<M, F, E>(
    state: &AppState,
    workers: &mut BackgroundWorkers,
    name: &'static str,
    make: M,
) where
    M: FnMut(ShutdownSignal) -> F + Send + 'static,
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    workers.tasks.spawn(supervise(
        state.lifecycle().subscribe_shutdown(),
        name,
        make,
    ));
}

async fn supervise<M, F, E>(mut shutdown: watch::Receiver<bool>, name: &'static str, mut make: M)
where
    M: FnMut(ShutdownSignal) -> F,
    F: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let mut delay = RESTART_DELAY;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let started = Instant::now();
        match make(shutdown_signal(shutdown.clone())).await {
            Ok(()) if *shutdown.borrow() => return,
            Ok(()) => warn!(worker = name, "background worker stopped; restarting"),
            Err(error) if *shutdown.borrow() => {
                warn!(worker = name, error = %error, "background worker stopped during shutdown");
                return;
            }
            Err(error) => {
                error!(worker = name, error = %error, "background worker failed; restarting")
            }
        }
        if started.elapsed() >= STABLE_RUN {
            delay = RESTART_DELAY;
        }
        select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.wait_for(|&stopped| stopped) => return,
        }
        delay = (delay * 2).min(MAX_RESTART_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{sync::watch, time::Instant};

    use super::{MAX_RESTART_DELAY, period_key, supervise};

    #[tokio::test(start_paused = true)]
    async fn a_failing_worker_is_restarted_with_growing_delays_until_shutdown() {
        let (stop, shutdown) = watch::channel(false);
        let starts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&starts);
        let begun = Instant::now();
        let supervisor = tokio::spawn(supervise(shutdown, "test", move |_| {
            recorded.lock().unwrap().push(begun.elapsed());
            async { Err::<(), _>("backend failed") }
        }));

        tokio::time::sleep(std::time::Duration::from_secs(200)).await;
        let gaps: Vec<_> = starts
            .lock()
            .unwrap()
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect();
        assert!(gaps.len() >= 6, "the worker keeps being started again");
        assert!(
            gaps.windows(2).all(|pair| pair[1] >= pair[0]),
            "delays only grow"
        );
        assert!(gaps.iter().all(|gap| *gap <= MAX_RESTART_DELAY));

        stop.send(true).unwrap();
        supervisor.await.unwrap();
        let after_stop = starts.lock().unwrap().len();
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        assert_eq!(
            starts.lock().unwrap().len(),
            after_stop,
            "no start after shutdown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_worker_is_left_alone_and_ends_on_shutdown() {
        let (stop, shutdown) = watch::channel(false);
        let starts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&starts);
        let supervisor = tokio::spawn(supervise(shutdown, "test", move |signal| {
            counted.fetch_add(1, Ordering::SeqCst);
            signal
        }));
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        stop.send(true).unwrap();
        supervisor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn an_already_signaled_shutdown_stops_without_starting_workers() {
        let (stop, shutdown) = watch::channel(false);
        stop.send(true).unwrap();
        let starts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&starts);
        supervise(shutdown, "test", move |signal| {
            counted.fetch_add(1, Ordering::SeqCst);
            signal
        })
        .await;
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_period_key_is_shared_within_the_period_only() {
        let hour = 3_600;
        let start = 1_790_000_000 - 1_790_000_000 % hour;
        assert_eq!(
            period_key("rotation", start, hour),
            period_key("rotation", start + hour - 1, hour)
        );
        assert_ne!(
            period_key("rotation", start, hour),
            period_key("rotation", start + hour, hour)
        );
    }
}
