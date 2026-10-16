//! Short-lived verification state, independent of any authentication SDK.
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeMethod {
    Passkey,
    SmsOtp,
    EmailOtp,
}

impl ChallengeMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "passkey",
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
