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
    /// Replacing a forgotten password from the sign-in flow.
    PasswordReset,
    /// Verifying the email address of an account being created from the
    /// sign-in flow. No account exists yet, so the challenge has no user.
    Registration,
    /// Verifying an account's address, or a new address that replaces it,
    /// from a link that needs no session.
    EmailVerification,
    /// Setting the first password of an account an administrator created.
    Invitation,
}

impl ChallengePurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::CredentialRegistration => "credential_registration",
            Self::PasswordReset => "password_reset",
            Self::Registration => "registration",
            Self::EmailVerification => "email_verification",
            Self::Invitation => "invitation",
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

/// How often the email (or text message) of one challenge may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryPolicy {
    /// Minimum time between two sends.
    pub resend_interval: Duration,
    /// Sends allowed per [`Self::window`], or over the challenge's whole life
    /// without one. `None` allows any number.
    pub max_sends: Option<i32>,
    /// The span `max_sends` is counted over. It starts with the first send
    /// and restarts once it has passed.
    pub window: Option<Duration>,
}

/// What was sent for a challenge so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryCounter {
    pub sent_at: DateTime<Utc>,
    pub send_count: i32,
    pub window_started_at: DateTime<Utc>,
}

/// Whether another send is admitted by a [`DeliveryPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDecision {
    /// Send now; store this counter with the new verifier.
    Admit(DeliveryCounter),
    TooSoon {
        available_at: DateTime<Utc>,
    },
    LimitReached,
}

fn after(at: DateTime<Utc>, span: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(span)
        .ok()
        .and_then(|span| at.checked_add_signed(span))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

impl DeliveryPolicy {
    /// When the next send is admitted after the one counted in `counter`.
    #[must_use]
    pub fn resend_available_at(&self, counter: &DeliveryCounter) -> DateTime<Utc> {
        after(counter.sent_at, self.resend_interval)
    }

    /// Decide on a send at `now` after the sends counted in `previous`.
    #[must_use]
    pub fn admit(
        &self,
        previous: Option<&DeliveryCounter>,
        now: DateTime<Utc>,
    ) -> DeliveryDecision {
        let Some(previous) = previous else {
            return DeliveryDecision::Admit(DeliveryCounter {
                sent_at: now,
                send_count: 1,
                window_started_at: now,
            });
        };
        let window_open = self
            .window
            .is_none_or(|window| now < after(previous.window_started_at, window));
        if window_open
            && self
                .max_sends
                .is_some_and(|max_sends| previous.send_count >= max_sends)
        {
            return DeliveryDecision::LimitReached;
        }
        let available_at = self.resend_available_at(previous);
        if now < available_at {
            return DeliveryDecision::TooSoon { available_at };
        }
        DeliveryDecision::Admit(if window_open {
            DeliveryCounter {
                sent_at: now,
                send_count: previous.send_count.saturating_add(1),
                window_started_at: previous.window_started_at,
            }
        } else {
            DeliveryCounter {
                sent_at: now,
                send_count: 1,
                window_started_at: now,
            }
        })
    }
}

/// Admission policy and newly generated verifier for an outbound challenge.
#[derive(Debug, Clone)]
pub struct DeliveryChallengeRequest {
    pub now: DateTime<Utc>,
    pub policy: DeliveryPolicy,
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

/// Persisted JSON state for an outbound delivery challenge. What was sent is
/// kept beside it as a [`DeliveryCounter`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryChallengeState {
    pub code_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).expect("valid time")
    }

    const DAILY: DeliveryPolicy = DeliveryPolicy {
        resend_interval: Duration::from_secs(60),
        max_sends: Some(2),
        window: Some(Duration::from_secs(3600)),
    };

    #[test]
    fn sends_wait_for_the_interval_and_stop_at_the_limit_until_the_window_passes() {
        let DeliveryDecision::Admit(first) = DAILY.admit(None, at(0)) else {
            panic!("first send is admitted");
        };
        assert_eq!(
            DAILY.admit(Some(&first), at(30)),
            DeliveryDecision::TooSoon {
                available_at: at(60)
            }
        );
        let DeliveryDecision::Admit(second) = DAILY.admit(Some(&first), at(60)) else {
            panic!("second send is admitted");
        };
        assert_eq!((second.send_count, second.window_started_at), (2, at(0)));
        assert_eq!(
            DAILY.admit(Some(&second), at(600)),
            DeliveryDecision::LimitReached
        );
        let DeliveryDecision::Admit(renewed) = DAILY.admit(Some(&second), at(3600)) else {
            panic!("a new window admits again");
        };
        assert_eq!(
            (renewed.send_count, renewed.window_started_at),
            (1, at(3600))
        );
    }

    #[test]
    fn without_a_window_the_limit_holds_for_the_challenge_and_none_means_unlimited() {
        let lifetime = DeliveryPolicy {
            window: None,
            ..DAILY
        };
        let counter = DeliveryCounter {
            sent_at: at(0),
            send_count: 2,
            window_started_at: at(0),
        };
        assert_eq!(
            lifetime.admit(Some(&counter), at(86_400)),
            DeliveryDecision::LimitReached
        );
        let unlimited = DeliveryPolicy {
            max_sends: None,
            ..lifetime
        };
        assert!(matches!(
            unlimited.admit(Some(&counter), at(86_400)),
            DeliveryDecision::Admit(DeliveryCounter { send_count: 3, .. })
        ));
    }
}
