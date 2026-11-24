//! Email verification state and payloads of the account center.

use async_graphql::{InputObject, Object, SimpleObject};
use chrono::{DateTime, Utc};
use identity_application::authentication::email_verification::{
    EmailVerificationSent, PendingEmailVerification,
};

use super::types::UserNode;

/// Whether the account can verify its email address, and the verification
/// in progress.
#[derive(SimpleObject)]
pub(crate) struct AccountEmailVerification {
    /// Whether this instance can send verification emails. Without it, a
    /// changed address is replaced at once and stays unverified.
    available: bool,
    /// The link that was sent and can still be followed.
    pending: Option<EmailVerificationRequest>,
}

impl AccountEmailVerification {
    pub(super) fn new(available: bool, pending: Option<PendingEmailVerification>) -> Self {
        Self {
            available,
            pending: pending.map(EmailVerificationRequest::from),
        }
    }
}

/// A verification link that was emailed.
#[derive(SimpleObject)]
pub(crate) struct EmailVerificationRequest {
    /// The address the link was sent to.
    email: String,
    /// Whether following the link replaces the account's current address.
    changes_email: bool,
    sent_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// When another link may be requested.
    resend_available_at: DateTime<Utc>,
}

impl From<PendingEmailVerification> for EmailVerificationRequest {
    fn from(value: PendingEmailVerification) -> Self {
        Self {
            email: value.verification.email,
            changes_email: value.verification.changes_email,
            sent_at: value.verification.sent_at,
            expires_at: value.verification.expires_at,
            resend_available_at: value.resend_available_at,
        }
    }
}

impl From<EmailVerificationSent> for EmailVerificationRequest {
    fn from(value: EmailVerificationSent) -> Self {
        Self::from(PendingEmailVerification {
            verification: value.verification,
            resend_available_at: value.resend_available_at,
        })
    }
}

#[derive(InputObject)]
pub(crate) struct SendEmailVerificationInput {
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(InputObject)]
pub(crate) struct CancelEmailVerificationInput {
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct UpdateEmailPayload {
    pub(super) user: UserNode,
    pub(super) verification: Option<EmailVerificationRequest>,
    pub(super) client_mutation_id: Option<String>,
}

#[Object]
impl UpdateEmailPayload {
    /// The account. Its address is unchanged while `verification` is set.
    async fn user(&self) -> &UserNode {
        &self.user
    }

    /// The link sent to the new address, which replaces the current one
    /// once followed.
    async fn verification(&self) -> Option<&EmailVerificationRequest> {
        self.verification.as_ref()
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[derive(SimpleObject)]
pub(crate) struct SendEmailVerificationPayload {
    pub(super) verification: EmailVerificationRequest,
    pub(super) client_mutation_id: Option<String>,
}

#[derive(SimpleObject)]
pub(crate) struct CancelEmailVerificationPayload {
    /// Whether a verification was in progress.
    pub(super) cancelled: bool,
    pub(super) client_mutation_id: Option<String>,
}
