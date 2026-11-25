//! Outgoing messages. A message is rendered when the change that causes it
//! is made, and queued in the same transaction, so a stored verification,
//! invitation or sign-in code always has its email on the way.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One rendered message to a single recipient. The sender adds a plain-text
/// alternative derived from the HTML body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMessage {
    pub to_address: String,
    pub to_name: Option<String>,
    pub subject: String,
    pub html: String,
}

impl std::fmt::Debug for EmailMessage {
    // Bodies carry sign-in codes and links; never print them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailMessage").finish_non_exhaustive()
    }
}

/// A message to queue with the change that causes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundEmail {
    /// The template kind, for diagnostics only.
    pub kind: &'static str,
    pub message: EmailMessage,
    /// When what the message carries stops working; a message still queued
    /// then is dropped instead of sent.
    pub expires_at: DateTime<Utc>,
}

/// Where a queued message stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailDeliveryStatus {
    /// Waiting for, or being tried by, a delivery worker.
    Queued,
    /// The mail server accepted it.
    Delivered,
    /// Given up; see [`EmailDeliveryFailure`].
    Failed,
}

/// Why a queued message was given up. Never carries server text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailDeliveryFailure {
    /// What it carried stopped working before it could be sent.
    Expired,
    /// Email delivery was turned off or is incomplete.
    NotConfigured,
    /// The mail server refused the address.
    InvalidAddress,
    /// The mail server refused the instance's credentials.
    AuthenticationFailed,
    /// The mail server refused the message for good, for example an
    /// unknown recipient.
    Rejected,
    /// The mail server could not be reached or kept failing.
    TransportFailed,
    /// The stored delivery secret could not be read.
    SecretUnavailable,
    /// The queued message could not be read back.
    MessageUnreadable,
}

/// The latest delivery outcome of a message, recorded on what it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailDeliveryReport {
    pub status: EmailDeliveryStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<EmailDeliveryFailure>,
    pub at: DateTime<Utc>,
}

impl EmailDeliveryReport {
    #[must_use]
    pub const fn queued(at: DateTime<Utc>) -> Self {
        Self {
            status: EmailDeliveryStatus::Queued,
            failure: None,
            at,
        }
    }

    #[must_use]
    pub const fn delivered(at: DateTime<Utc>) -> Self {
        Self {
            status: EmailDeliveryStatus::Delivered,
            failure: None,
            at,
        }
    }

    #[must_use]
    pub const fn failed(failure: EmailDeliveryFailure, at: DateTime<Utc>) -> Self {
        Self {
            status: EmailDeliveryStatus::Failed,
            failure: Some(failure),
            at,
        }
    }
}
