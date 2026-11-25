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
