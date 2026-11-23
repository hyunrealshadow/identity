//! Persistence port shared by Passkey and future SMS/email OTP use cases.
use crate::error::AppError;
use async_trait::async_trait;
use identity_domain::auth::challenge::{
    AuthenticationChallenge, ChallengeBinding, ChallengeContext, ChallengeMethod, ChallengePurpose,
    DeliveryChallengeAdmission, DeliveryChallengeContext, DeliveryChallengeRequest,
    DeliveryChallengeStatus,
};
use uuid::Uuid;

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    /// Create an independent challenge on a live interaction owned by this user.
    async fn store(
        &self,
        context: ChallengeContext,
        challenge: AuthenticationChallenge,
    ) -> Result<(), AppError>;

    /// Atomically enforce resend interval and send limits on an outbound
    /// delivery challenge and store its new verifier when provided.
    async fn admit_delivery(
        &self,
        context: DeliveryChallengeContext,
        request: DeliveryChallengeRequest,
    ) -> Result<DeliveryChallengeAdmission, AppError>;

    /// Return the latest outbound delivery status for an active interaction
    /// without checking or revealing whether an account matched.
    async fn delivery_status(
        &self,
        binding: ChallengeBinding,
        method: ChallengeMethod,
        purpose: ChallengePurpose,
    ) -> Result<Option<DeliveryChallengeStatus>, AppError>;

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
