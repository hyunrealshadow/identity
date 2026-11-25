//! Email address verification. An account has at most one outstanding
//! verification: either of the address it already has, or of a new address
//! that replaces the current one only once it is verified. The emailed link
//! carries a random token of which only a digest is stored.
//!
//! A verification is tied to the address the account had when it was
//! requested. Any later change of that address voids it, so neither an
//! administrator's change nor another verification can be undone by an
//! older link.

use std::{error::Error as StdError, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::UserOid;
use crate::auth::challenge::DeliveryPolicy;

/// How long an emailed verification link stays valid.
pub const EMAIL_VERIFICATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Minimum time between two verification emails of one account.
pub const EMAIL_VERIFICATION_RESEND_INTERVAL: Duration = Duration::from_secs(60);
/// Verification emails one account may request within
/// [`EMAIL_VERIFICATION_SEND_WINDOW`].
pub const MAX_EMAIL_VERIFICATION_SENDS: i32 = 5;
/// The window over which [`MAX_EMAIL_VERIFICATION_SENDS`] is counted. It
/// starts with the first email and restarts after it has passed.
pub const EMAIL_VERIFICATION_SEND_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// How often one account may be sent a verification email, whichever
/// address each one went to.
pub const EMAIL_VERIFICATION_DELIVERY: DeliveryPolicy = DeliveryPolicy {
    resend_interval: EMAIL_VERIFICATION_RESEND_INTERVAL,
    max_sends: Some(MAX_EMAIL_VERIFICATION_SENDS),
    window: Some(EMAIL_VERIFICATION_SEND_WINDOW),
};

/// An outstanding verification as shown to its account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailVerification {
    pub oid: Uuid,
    pub user_oid: UserOid,
    /// The address being verified, as entered.
    pub email: String,
    pub email_normalized: String,
    /// Whether verifying it replaces the account's current address.
    pub changes_email: bool,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A request to email a new verification link.
#[derive(Debug, Clone)]
pub struct EmailVerificationRequest {
    pub user_oid: UserOid,
    /// The address to verify, as entered, and its normalized form.
    pub email: String,
    pub email_normalized: String,
    /// SHA-256 of the new link token, base64url.
    pub token_digest: String,
    pub now: DateTime<Utc>,
}

/// Outcome of an atomic verification admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailVerificationAdmission {
    /// The new link replaces any earlier one; the caller sends it.
    Admitted {
        verification: EmailVerification,
        resend_available_at: DateTime<Utc>,
    },
    TooSoon {
        available_at: DateTime<Utc>,
    },
    LimitReached,
    /// The account's current address is already verified.
    AlreadyVerified,
    /// Another account uses the address.
    EmailExists,
    UserNotFound,
}

/// Outcome of following a verification link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailVerificationOutcome {
    Verified {
        user_oid: UserOid,
        email: String,
        /// Whether the account's address was replaced.
        changed: bool,
    },
    /// Unknown, expired, already used, or voided by a later change.
    Invalid,
    /// Another account took the address in the meantime.
    EmailExists,
}

#[derive(Debug, Error)]
pub enum EmailVerificationRepositoryError {
    #[error("failed to access email verifications")]
    QueryFailed(#[source] Box<dyn StdError + Send + Sync>),
}

#[async_trait]
pub trait EmailVerificationRepository: Send + Sync {
    /// Enforce the resend interval and send limit, then store the request as
    /// the account's only outstanding verification, tied to the address the
    /// account has now.
    async fn admit(
        &self,
        request: EmailVerificationRequest,
    ) -> Result<EmailVerificationAdmission, EmailVerificationRepositoryError>;

    /// The account's outstanding verification, if it is still usable.
    async fn pending(
        &self,
        user_oid: UserOid,
        now: DateTime<Utc>,
    ) -> Result<Option<EmailVerification>, EmailVerificationRepositoryError>;

    /// Discard the account's outstanding verification. Returns whether one
    /// existed.
    async fn cancel(&self, user_oid: UserOid) -> Result<bool, EmailVerificationRepositoryError>;

    /// Consume the verification whose link token has `token_digest` and
    /// apply it: mark the address verified, replacing the account's address
    /// when it differs, and audit the change, all in one transaction.
    async fn confirm(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<EmailVerificationOutcome, EmailVerificationRepositoryError>;
}
