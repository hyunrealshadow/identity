//! The outgoing email queue. A message is written to the job queue in the
//! same transaction as the change that causes it, so a stored verification,
//! invitation or sign-in code always has its email on the way, and a
//! refused change queues nothing. The queued job holds the message only in
//! data-protected form: its body carries codes and links.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use identity_application::data_protection::DataProtector;
use identity_domain::email::{EmailMessage, OutboundEmail};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use uuid::Uuid;

/// The job queue that delivers outgoing email.
pub const EMAIL_QUEUE: &str = "identity.email";

/// Data-protection purpose of a queued message.
const QUEUED_EMAIL_PURPOSE: &str = "email.queue.message";

/// One queued message. Only `kind` and `expires_at` are readable without
/// the data-protection key.
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailJob {
    pub kind: String,
    pub expires_at: DateTime<Utc>,
    pub message: String,
    /// The account challenge whose link the message carries; its delivery
    /// outcome is recorded there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_to: Option<Uuid>,
}

impl std::fmt::Debug for EmailJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailJob")
            .field("kind", &self.kind)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Writes messages to the queue and reads them back for delivery.
#[derive(Clone)]
pub struct EmailQueue {
    protector: Arc<dyn DataProtector>,
    queue: String,
}

fn failed(error: impl std::fmt::Display) -> DbErr {
    DbErr::Custom(format!("email could not be queued: {error}"))
}

impl EmailQueue {
    #[must_use]
    pub fn new(protector: Arc<dyn DataProtector>) -> Self {
        Self {
            protector,
            queue: EMAIL_QUEUE.to_owned(),
        }
    }

    /// Write to another queue than the one the email workers read, so a
    /// test's messages stay apart from a running instance's.
    #[must_use]
    pub fn with_queue(mut self, queue: impl Into<String>) -> Self {
        self.queue = queue.into();
        self
    }

    /// Queue `email` inside the caller's transaction; it is delivered only
    /// if the transaction commits. The outcome is recorded on the account
    /// challenge `report_to` when given.
    pub async fn enqueue(
        &self,
        connection: &impl ConnectionTrait,
        email: &OutboundEmail,
        report_to: Option<Uuid>,
    ) -> Result<(), DbErr> {
        let plain = serde_json::to_vec(&email.message).map_err(failed)?;
        let message = self
            .protector
            .protect(QUEUED_EMAIL_PURPOSE, &plain)
            .await
            .map_err(failed)?;
        let job = serde_json::to_vec(&EmailJob {
            kind: email.kind.to_owned(),
            expires_at: email.expires_at,
            message,
            report_to,
        })
        .map_err(failed)?;
        // The columns apalis-postgres writes for a new task; the queue's own
        // trigger wakes the workers when the transaction commits.
        connection
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO apalis.jobs (id, job_type, job, status, attempts, max_attempts, run_at, priority) \
                 VALUES ($1, $2, $3, 'Pending', 0, 1, now(), 0)",
                [
                    Ulid::generate().to_string().into(),
                    self.queue.clone().into(),
                    job.into(),
                ],
            ))
            .await?;
        Ok(())
    }

    /// The message of a queued job, or a bounded reason why it cannot be
    /// read.
    pub async fn open(&self, job: &EmailJob) -> Result<EmailMessage, &'static str> {
        let plain = self
            .protector
            .unprotect(QUEUED_EMAIL_PURPOSE, &job.message)
            .await
            .map_err(|_| "message_unreadable")?;
        serde_json::from_slice(&plain).map_err(|_| "message_unreadable")
    }
}
