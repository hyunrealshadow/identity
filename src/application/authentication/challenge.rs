//! Persistence port shared by Passkey and future SMS/email OTP use cases.
use crate::error::AppError;
use async_trait::async_trait;
use identity_domain::auth::challenge::{AuthenticationChallenge, ChallengeContext};
use uuid::Uuid;

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    /// Create an independent challenge on a live interaction owned by this user.
    async fn store(
        &self,
        context: ChallengeContext,
        challenge: AuthenticationChallenge,
    ) -> Result<(), AppError>;

    /// Atomically remove and return one unexpired challenge matching the entire
    /// context. Used by Passkey before verification, including failed assertions.
    /// Retry/attempt limits for OTP are a separate verification policy.
    async fn take(
        &self,
        context: ChallengeContext,
        id: Uuid,
    ) -> Result<Option<AuthenticationChallenge>, AppError>;

    /// Return the most recent unexpired challenge matching the entire context
    /// without consuming it. Used by multi-step registrations that a page
    /// reload or a rejected confirmation must be able to resume.
    async fn latest(
        &self,
        context: ChallengeContext,
    ) -> Result<Option<AuthenticationChallenge>, AppError>;
}
