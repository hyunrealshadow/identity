//! Delivers queued email. Workers wake on the queue's notification when a
//! transaction that queued a message commits. A transient failure is tried
//! again after a growing delay while what the message carries still works;
//! a permanent one, or a message that has expired, is given up and reported.
//! A worker that dies mid-delivery has its message picked up again once its
//! heartbeat lapses, so a message may rarely arrive twice.

use std::time::Duration;

use apalis::prelude::{AbortError, BoxDynError, Data, WorkerBuilder};
use apalis_postgres::{Config, PostgresStorage};
use chrono::Utc;
use identity_application::{
    email::EmailDeliveryError,
    observability::{BusinessEvent, EventValue, event_sink},
    setting::{EmailDeliverySettings, SettingsSource as _},
};
use sea_orm::sqlx::PgPool;
use tracing::{Instrument, info, info_span, warn};
use uuid::Uuid;

use super::spawn_until_shutdown;
use crate::{
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

/// Failures that another attempt cannot fix; an operator has to change the
/// delivery settings or the address first.
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

/// Stop working on the message. The recorded error is a bounded reason,
/// never the message.
fn give_up(job: &EmailJob, reason: &'static str, attempts: usize) -> BoxDynError {
    warn!(email_kind = %job.kind, reason, attempts, "queued email given up");
    report(&job.kind, "abandoned", Some(reason), attempts);
    Box::new(AbortError::new(reason))
}

async fn deliver(job: EmailJob, state: Data<AppState>) -> Result<(), BoxDynError> {
    let span = info_span!("email.deliver", email.kind = %job.kind);
    async move {
        let services = state.services();
        let message = match services.email_queue().open(&job).await {
            Ok(message) => message,
            Err(reason) => return Err(give_up(&job, reason, 0)),
        };
        let mut attempts = 0;
        loop {
            if Utc::now() >= job.expires_at {
                return Err(give_up(&job, "expired", attempts));
            }
            // The settings in force now, not when the message was queued.
            let delivery = state
                .settings()
                .store()
                .snapshot()
                .section::<EmailDeliverySettings>();
            if !delivery.is_configured() {
                return Err(give_up(&job, "not_configured", attempts));
            }
            attempts += 1;
            match services
                .email_sender()
                .send(&delivery, message.clone())
                .await
            {
                Ok(()) => {
                    info!(email_kind = %job.kind, attempts, "queued email delivered");
                    report(&job.kind, "delivered", None, attempts);
                    return Ok(());
                }
                Err(error) if permanent(&error) => {
                    return Err(give_up(&job, error.reason(), attempts));
                }
                Err(error) => {
                    let Some(delay) = RETRY_DELAYS.get(attempts - 1) else {
                        return Err(give_up(&job, error.reason(), attempts));
                    };
                    warn!(
                        email_kind = %job.kind,
                        reason = error.reason(),
                        attempts,
                        retry_in_seconds = delay.as_secs(),
                        "queued email delivery failed; trying again"
                    );
                    tokio::time::sleep(*delay).await;
                }
            }
        }
    }
    .instrument(span)
    .await
}

pub(super) fn spawn_email_workers(state: &AppState, pool: &PgPool) {
    let pool = pool.clone();
    let worker_state = state.clone();
    spawn_until_shutdown(state, "email-delivery", move || {
        let storage = PostgresStorage::<EmailJob>::new(&pool)
            .with_config(Config::default().queue(EMAIL_QUEUE))
            // Wake on the queue's notification instead of waiting for a poll.
            .with_pubsub();
        WorkerBuilder::new(format!("email-delivery-{}", Uuid::new_v4()))
            .backend(storage)
            .data(worker_state.clone())
            .build(deliver)
            .run()
    });
}
