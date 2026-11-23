//! Short-lived verification state, independent of any authentication SDK.
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::LoginStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeMethod {
    Passkey,
    Totp,
    SmsOtp,
    EmailOtp,
}

impl ChallengeMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "passkey",
            Self::Totp => "totp",
            Self::SmsOtp => "sms_otp",
            Self::EmailOtp => "email_otp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengePurpose {
    Authentication,
    CredentialRegistration,
}

impl ChallengePurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::CredentialRegistration => "credential_registration",
        }
    }
}

/// The interaction that authorizes the challenge, not just the target account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeBinding {
    Login(Uuid),
    Session(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeContext {
    pub user_oid: Uuid,
    pub binding: ChallengeBinding,
    pub method: ChallengeMethod,
    pub purpose: ChallengePurpose,
}

/// Opaque verifier state. Never return it to the browser or include it in logs.
/// OTP implementations must store a protected verifier, never a plaintext code.
#[derive(Clone)]
pub struct AuthenticationChallenge {
    pub id: Uuid,
    pub state: serde_json::Value,
    pub expires_at: DateTime<Utc>,
}

/// Interaction target for an outbound delivery challenge.
/// `user_oid` is `None` while the login conceals whether an account matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryChallengeContext {
    pub user_oid: Option<Uuid>,
    pub binding: ChallengeBinding,
    pub method: ChallengeMethod,
    pub purpose: ChallengePurpose,
}

/// Admission policy and newly generated verifier for an outbound challenge.
#[derive(Debug, Clone)]
pub struct DeliveryChallengeRequest {
    pub now: DateTime<Utc>,
    pub resend_interval: Duration,
    pub max_sends: i32,
    pub code_expires_at: DateTime<Utc>,
    pub required_login_status: Option<LoginStatus>,
    pub verifier: Option<serde_json::Value>,
}

/// Outcome of an atomic outbound challenge admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryChallengeAdmission {
    Admitted {
        sent_at: DateTime<Utc>,
        send_count: i32,
        resend_available_at: DateTime<Utc>,
    },
    TooSoon {
        available_at: DateTime<Utc>,
    },
    LimitReached,
    InvalidState,
}

/// Current outbound challenge delivery status for an active interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryChallengeStatus {
    pub sent_at: DateTime<Utc>,
    pub send_count: i32,
}

/// Persisted JSON state for an outbound delivery challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryChallengeState {
    pub sent_at: DateTime<Utc>,
    pub send_count: i32,
    pub code_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<serde_json::Value>,
}
