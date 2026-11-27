//! Delivers queued email. Workers wake on the queue's notification when a
//! transaction that queued a message commits. A transient failure is tried
//! again after a growing delay while what the message carries still works;
//! a permanent one, or a message that has expired, is given up and reported.
//! A worker that dies mid-delivery has its message picked up again once its
//! heartbeat lapses, so a message may rarely arrive twice.

use std::time::Duration;

use apalis::prelude::{
    AbortError, BackendExt, BoxDynError, Data, ParallelizeExt, Strategy, WorkerBuilder,
    WorkerBuilderExt,
};
use apalis_postgres::{Config, PostgresStorage, Pubsub};
use chrono::Utc;
use identity_application::{
    email::EmailDeliveryError,
    key::runtime::RuntimeKeyRingProvider as _,
    observability::{BusinessEvent, EventValue, event_sink},
    setting::{EmailDeliverySettings, SettingsSource as _},
};
use sea_orm::sqlx::PgPool;
use tracing::{Instrument, info, info_span, warn};
use uuid::Uuid;

use super::{BackgroundWorkers, spawn_until_shutdown};
use identity_domain::email::{EmailDeliveryFailure, EmailDeliveryReport, EmailMessage};

use crate::{
    database::repository::account_challenge::record_delivery,
    email::{EMAIL_QUEUE, EmailJob},
    state::AppState,
};

/// Waits between attempts; the last failure gives the message up.
const RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];
/// Maximum number of email deliveries running concurrently on one worker.
const EMAIL_CONCURRENCY: usize = 4;
/// Fallback poll interval for delayed retries whose `run_at` lies in the future.
const DELAYED_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Failures that another attempt cannot fix; an operator has to change the
/// delivery settings or the address first. Only a transport failure may
/// pass.
fn permanent(error: &EmailDeliveryError) -> bool {
    !matches!(error, EmailDeliveryError::Transport { .. })
}

fn report(kind: &str, outcome: &'static str, reason: Option<&'static str>, attempts: usize) {
    let mut event = BusinessEvent::business("email.delivery")
        .outcome(outcome)
        .attribute("email_kind", EventValue::Text(kind.to_owned()))
        .attribute(
            "attempts",
            EventValue::Integer(i64::try_from(attempts).unwrap_or(i64::MAX)),
        );
    if let Some(reason) = reason {
        event = event.attribute("reason", EventValue::Text(reason.to_owned()));
    }
    event_sink().emit(event);
}

/// The bounded failure a delivery error stands for.
const fn failure_of(error: &EmailDeliveryError) -> EmailDeliveryFailure {
    match error {
        EmailDeliveryError::NotConfigured => EmailDeliveryFailure::NotConfigured,
        EmailDeliveryError::InvalidAddress => EmailDeliveryFailure::InvalidAddress,
        EmailDeliveryError::SecretUnavailable => EmailDeliveryFailure::SecretUnavailable,
        EmailDeliveryError::Authentication { .. } => EmailDeliveryFailure::AuthenticationFailed,
        EmailDeliveryError::Rejected { .. } => EmailDeliveryFailure::Rejected,
        EmailDeliveryError::Transport { .. } => EmailDeliveryFailure::TransportFailed,
    }
}

const fn reason_of(failure: EmailDeliveryFailure) -> &'static str {
    match failure {
        EmailDeliveryFailure::Expired => "expired",
        EmailDeliveryFailure::NotConfigured => "not_configured",
        EmailDeliveryFailure::InvalidAddress => "invalid_address",
        EmailDeliveryFailure::AuthenticationFailed => "authentication_failed",
        EmailDeliveryFailure::Rejected => "rejected",
        EmailDeliveryFailure::TransportFailed => "transport_failed",
        EmailDeliveryFailure::SecretUnavailable => "secret_unavailable",
        EmailDeliveryFailure::MessageUnreadable => "message_unreadable",
    }
}

/// Record the outcome on the challenge the message carries a link of, so
/// administrators can see it. A failure to record it is only logged.
async fn record(state: &AppState, job: &EmailJob, report: EmailDeliveryReport) {
    let Some(oid) = job.report_to else {
        return;
    };
    if let Err(error) = record_delivery(state.resources().db(), oid, &report).await {
        warn!(email_kind = %job.kind, error = %error, "email delivery outcome not recorded");
    }
}

/// Stop working on the message. The recorded error is a bounded reason,
/// never the message.
async fn give_up(
    state: &AppState,
    job: &EmailJob,
    failure: EmailDeliveryFailure,
    attempts: usize,
) -> BoxDynError {
    let reason = reason_of(failure);
    warn!(email_kind = %job.kind, reason, attempts, "queued email given up");
    report(&job.kind, "abandoned", Some(reason), attempts);
    record(state, job, EmailDeliveryReport::failed(failure, Utc::now())).await;
    Box::new(AbortError::new(reason))
}

async fn open_message(state: &AppState, job: &EmailJob) -> Result<EmailMessage, ()> {
    let queue = state.services().email_queue();
    if let Ok(message) = queue.open(job).await {
        return Ok(message);
    }
    // A peer instance may have rotated keys right before queuing this job.
    if let Err(error) = state.settings().key_ring().refresh_value().await {
        warn!(email_kind = %job.kind, error = %error, "key ring refresh failed");
    }
    queue.open(job).await.map_err(|_| ())
}

async fn configured_delivery(state: &AppState, kind: &str) -> Option<EmailDeliverySettings> {
    let delivery = state
        .settings()
        .store()
        .snapshot()
        .section::<EmailDeliverySettings>();
    if delivery.is_configured() {
        return Some(delivery);
    }
    // A peer instance may have enabled or updated delivery settings seconds ago.
    if let Err(error) = state.settings().store().refresh().await {
        warn!(email_kind = %kind, error = %error, "settings refresh failed");
    }
    let delivery = state
        .settings()
        .store()
        .snapshot()
        .section::<EmailDeliverySettings>();
    delivery.is_configured().then_some(delivery)
}

async fn deliver(job: EmailJob, state: Data<AppState>) -> Result<(), BoxDynError> {
    let span = info_span!("email.deliver", email.kind = %job.kind);
    async move {
        let prior_attempts = usize::try_from(job.prior_attempts).unwrap_or(usize::MAX);
        if Utc::now() >= job.expires_at {
            return Err(give_up(&state, &job, EmailDeliveryFailure::Expired, prior_attempts).await);
        }
        let Ok(message) = open_message(&state, &job).await else {
            return Err(give_up(
                &state,
                &job,
                EmailDeliveryFailure::MessageUnreadable,
                prior_attempts,
            )
            .await);
        };
        // The settings in force now, not when the message was queued.
        let Some(mut delivery) = configured_delivery(&state, &job.kind).await else {
            return Err(give_up(
                &state,
                &job,
                EmailDeliveryFailure::NotConfigured,
                prior_attempts,
            )
            .await);
        };

        let services = state.services();
        let attempts = prior_attempts.saturating_add(1);
        let mut outcome = services
            .email_sender()
            .send(&delivery, message.clone())
            .await;
        if matches!(outcome, Err(EmailDeliveryError::SecretUnavailable)) {
            if let Err(error) = state.settings().store().refresh().await {
                warn!(email_kind = %job.kind, error = %error, "settings refresh failed");
            }
            delivery = state
                .settings()
                .store()
                .snapshot()
                .section::<EmailDeliverySettings>();
            if !delivery.is_configured() {
                return Err(
                    give_up(&state, &job, EmailDeliveryFailure::NotConfigured, attempts).await,
                );
            }
            outcome = services
                .email_sender()
                .send(&delivery, message.clone())
                .await;
        }

        match outcome {
            Ok(()) => {
                info!(email_kind = %job.kind, attempts, "queued email delivered");
                report(&job.kind, "delivered", None, attempts);
                record(&state, &job, EmailDeliveryReport::delivered(Utc::now())).await;
                Ok(())
            }
            Err(error) if permanent(&error) => {
                Err(give_up(&state, &job, failure_of(&error), attempts).await)
            }
            Err(error) => {
                let Some(delay) = RETRY_DELAYS.get(prior_attempts) else {
                    return Err(give_up(&state, &job, failure_of(&error), attempts).await);
                };
                let retry_at = Utc::now()
                    + chrono::Duration::from_std(*delay).unwrap_or(chrono::Duration::MAX);
                if retry_at >= job.expires_at {
                    return Err(give_up(&state, &job, failure_of(&error), attempts).await);
                }
                let mut next_job = job.clone();
                next_job.prior_attempts = job.prior_attempts.saturating_add(1);
                if let Err(requeue_error) = services
                    .email_queue()
                    .requeue_after(state.resources().db(), &next_job, retry_at)
                    .await
                {
                    warn!(
                        email_kind = %job.kind,
                        error = %requeue_error,
                        "failed to schedule queued email retry"
                    );
                    return Err(give_up(&state, &job, failure_of(&error), attempts).await);
                }
                warn!(
                    email_kind = %job.kind,
                    reason = error.reason(),
                    attempts,
                    retry_in_seconds = delay.as_secs(),
                    "queued email delivery failed; trying again"
                );
                Ok(())
            }
        }
    }
    .instrument(span)
    .await
}

pub(super) fn spawn_email_workers(
    state: &AppState,
    pool: &PgPool,
    workers: &mut BackgroundWorkers,
) {
    let pool = pool.clone();
    let worker_state = state.clone();
    spawn_until_shutdown(state, workers, "email-delivery", move |signal| {
        let config = Config::default()
            .queue(EMAIL_QUEUE)
            .batch_size(EMAIL_CONCURRENCY);
        // Wake immediately on insert notifications, and poll briefly so
        // delayed retries whose `run_at` is in the future are picked up.
        let strategy = Strategy::new()
            .stream(Pubsub::new(pool.clone(), EMAIL_QUEUE.to_owned()))
            .interval(DELAYED_POLL_INTERVAL);
        let storage = PostgresStorage::<EmailJob>::new(&pool)
            .with_config(config)
            .poll_with_strategy(strategy);
        WorkerBuilder::new(format!("email-delivery-{}", Uuid::new_v4()))
            .backend(storage)
            .data(worker_state.clone())
            .parallelize(tokio::spawn)
            .concurrency(EMAIL_CONCURRENCY)
            .build(deliver)
            .run_until(signal)
    });
}
