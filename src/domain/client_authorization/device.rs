//! Device authorization state (RFC 8628).
//!
//! A device request is short lived: it carries the polling schedule, the
//! hashed device code, the user code a person types at the verification URI
//! and the outcome of the user's decision. Approving it creates a
//! [`DeviceAuthorizationData`] relation that outlives both the request and the
//! browser session used to approve it (ADR 0004).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum::{AsRefStr, Display};
use uuid::Uuid;

/// Characters used for user codes: upper-case consonants without vowels, so a
/// generated code cannot spell a word and stays unambiguous when typed.
pub const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Number of characters in a user code.
pub const USER_CODE_LENGTH: usize = 8;

/// Seconds added to the polling interval every time a client polls too early
/// (RFC 8628 §3.5).
pub const SLOW_DOWN_INCREMENT_SECONDS: i64 = 5;

/// Normalizes a user-typed code for lookup: upper-cased, with separators and
/// any character outside the code alphabet removed.
#[must_use]
pub fn normalize_user_code(input: &str) -> String {
    input
        .chars()
        .filter_map(|character| {
            let character = character.to_ascii_uppercase();
            (character.is_ascii() && USER_CODE_ALPHABET.contains(&(character as u8)))
                .then_some(character)
        })
        .collect()
}

/// Formats a normalized user code for display, grouped in fours:
/// `WDJBMJHT` becomes `WDJB-MJHT`.
#[must_use]
pub fn format_user_code(normalized: &str) -> String {
    normalized
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// SHA-256 digest of a device code, base64url without padding.
///
/// Only the digest is persisted, so a database leak does not expose codes that
/// can still be redeemed.
#[must_use]
pub fn device_code_digest(device_code: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(device_code.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, AsRefStr, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DeviceRequestStatus {
    /// Waiting for the user to approve or deny at the verification URI.
    #[default]
    Pending,
    /// Approved by the user; the client has not redeemed the device code yet.
    Approved,
    /// Denied by the user.
    Denied,
    /// Redeemed: tokens were issued in the same transaction.
    Consumed,
}

/// Outcome of a completed user decision on a device request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationApproval {
    pub user_oid: String,
    pub approved_scope: String,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    /// Relation created by this approval.
    pub device_authorization_oid: Uuid,
}

/// Short-lived device authorization request (stored as its own
/// `client_authorization` row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequestData {
    /// Requested scope, exactly as parsed from the device authorization request.
    pub scope: String,
    /// Digest of the device code handed to the client.
    pub device_code_digest: String,
    /// Normalized user code used for lookups.
    pub user_code: String,
    /// Login that consumed the user code. The request stays pending until consent.
    #[serde(default)]
    pub claimed_login_oid: Option<Uuid>,
    /// Display form of the user code.
    pub user_code_display: String,
    /// Polling interval advertised to the client.
    pub interval_seconds: i64,
    /// Extra seconds accumulated by too-frequent polling.
    #[serde(default)]
    pub slow_down_seconds: i64,
    /// When the last poll was accepted.
    #[serde(default)]
    pub last_polled_at: Option<DateTime<Utc>>,
    pub status: DeviceRequestStatus,
    /// Set once the user approves the request.
    #[serde(default)]
    pub approval: Option<DeviceAuthorizationApproval>,
    /// Set once the user denies the request.
    #[serde(default)]
    pub denied_by_user_oid: Option<String>,
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    /// Relation created by the approval, mirrored from `approval`.
    #[serde(default)]
    pub device_authorization_oid: Option<Uuid>,
}

/// Long-lived grant established by approving a device request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationData {
    /// Scope actually granted (a subset of the requested scope).
    pub scope: String,
    pub user_oid: String,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    /// Request row this relation was created from.
    pub request_oid: Uuid,
    pub approved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceRequestTransitionError {
    #[error("device request is not pending")]
    NotPending,
    #[error("device request is not approved")]
    NotApproved,
}

impl DeviceAuthorizationRequestData {
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self.status, DeviceRequestStatus::Pending)
    }

    #[must_use]
    pub const fn is_approved(&self) -> bool {
        matches!(self.status, DeviceRequestStatus::Approved)
    }

    /// Records an approval. Only a pending request can be approved, so a
    /// decision that was already taken can never be overwritten.
    pub fn approve(
        &mut self,
        approval: DeviceAuthorizationApproval,
        decided_at: DateTime<Utc>,
    ) -> Result<(), DeviceRequestTransitionError> {
        if !self.is_pending() {
            return Err(DeviceRequestTransitionError::NotPending);
        }

        self.device_authorization_oid = Some(approval.device_authorization_oid);
        self.approval = Some(approval);
        self.status = DeviceRequestStatus::Approved;
        self.decided_at = Some(decided_at);
        Ok(())
    }

    /// Records a denial. Only a pending request can be denied.
    pub fn deny(
        &mut self,
        user_oid: Uuid,
        decided_at: DateTime<Utc>,
    ) -> Result<(), DeviceRequestTransitionError> {
        if !self.is_pending() {
            return Err(DeviceRequestTransitionError::NotPending);
        }

        self.denied_by_user_oid = Some(user_oid.to_string());
        self.status = DeviceRequestStatus::Denied;
        self.decided_at = Some(decided_at);
        Ok(())
    }

    /// Marks the request redeemed. Only an approved request can be consumed,
    /// so a device code can never be redeemed twice.
    pub fn consume(&mut self) -> Result<(), DeviceRequestTransitionError> {
        if !self.is_approved() {
            return Err(DeviceRequestTransitionError::NotApproved);
        }

        self.status = DeviceRequestStatus::Consumed;
        Ok(())
    }

    /// Effective polling interval: the advertised interval plus everything
    /// accumulated by too-frequent polling.
    #[must_use]
    pub fn effective_interval_seconds(&self) -> i64 {
        self.interval_seconds
            .saturating_add(self.slow_down_seconds)
            .max(0)
    }
}

/// Result of the atomic poll-schedule update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePollOutcome {
    /// The poll arrived after the effective interval and was recorded.
    Accepted,
    /// The poll arrived too early; the effective interval grew by
    /// [`SLOW_DOWN_INCREMENT_SECONDS`].
    TooFrequent,
    /// The request is gone or no longer pollable (decided, consumed, revoked
    /// or expired); the caller re-reads the row to report why.
    NotPollable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_data() -> DeviceAuthorizationRequestData {
        DeviceAuthorizationRequestData {
            scope: "openid profile offline_access".to_owned(),
            device_code_digest: device_code_digest("device-code"),
            claimed_login_oid: None,
            user_code: "WDJBMJHT".to_owned(),
            user_code_display: "WDJB-MJHT".to_owned(),
            interval_seconds: 5,
            slow_down_seconds: 0,
            last_polled_at: None,
            status: DeviceRequestStatus::Pending,
            approval: None,
            denied_by_user_oid: None,
            decided_at: None,
            device_authorization_oid: None,
        }
    }

    fn approval() -> DeviceAuthorizationApproval {
        DeviceAuthorizationApproval {
            user_oid: Uuid::nil().to_string(),
            approved_scope: "openid profile".to_owned(),
            auth_time: Some(1_700_000_000),
            acr: Some("urn:identity:acr:aal1".to_owned()),
            amr: vec!["pwd".to_owned()],
            device_authorization_oid: Uuid::new_v4(),
        }
    }

    #[test]
    fn user_codes_normalize_and_display() {
        assert_eq!(normalize_user_code("wdjb-mjht"), "WDJBMJHT");
        assert_eq!(normalize_user_code("WDJB MJHT"), "WDJBMJHT");
        // Characters outside the alphabet (vowels, digits, punctuation) drop out.
        assert_eq!(normalize_user_code("w4jb-mj1t"), "WJBMJT");
        assert_eq!(format_user_code("WDJBMJHT"), "WDJB-MJHT");
    }

    #[test]
    fn device_code_digest_is_stable_and_hides_the_code() {
        let digest = device_code_digest("device-code");

        assert_eq!(digest, device_code_digest("device-code"));
        assert_ne!(digest, device_code_digest("other-code"));
        assert!(!digest.contains("device-code"));
    }

    #[test]
    fn approved_request_cannot_be_approved_or_denied_again() {
        let now = Utc::now();
        let mut request = request_data();
        request.approve(approval(), now).unwrap();

        assert_eq!(request.status, DeviceRequestStatus::Approved);
        assert!(request.approve(approval(), now).is_err());
        assert!(request.deny(Uuid::new_v4(), now).is_err());
        assert_eq!(request.status, DeviceRequestStatus::Approved);
    }

    #[test]
    fn denied_request_cannot_be_approved() {
        let now = Utc::now();
        let mut request = request_data();
        request.deny(Uuid::new_v4(), now).unwrap();

        assert_eq!(request.status, DeviceRequestStatus::Denied);
        assert!(request.approve(approval(), now).is_err());
        assert_eq!(request.approval, None);
    }

    #[test]
    fn only_approved_requests_can_be_consumed() {
        let now = Utc::now();
        let mut request = request_data();
        assert!(request.consume().is_err());

        request.approve(approval(), now).unwrap();
        request.consume().unwrap();
        assert_eq!(request.status, DeviceRequestStatus::Consumed);
        assert!(request.consume().is_err());
    }

    #[test]
    fn effective_interval_grows_with_slow_downs() {
        let mut request = request_data();
        assert_eq!(request.effective_interval_seconds(), 5);

        request.slow_down_seconds = SLOW_DOWN_INCREMENT_SECONDS * 2;
        assert_eq!(request.effective_interval_seconds(), 15);
    }

    #[test]
    fn stored_requests_survive_missing_optional_fields() {
        let stored = serde_json::json!({
            "scope": "openid",
            "device_code_digest": "digest",
            "user_code": "WDJBMJHT",
            "user_code_display": "WDJB-MJHT",
            "interval_seconds": 5,
            "status": "pending",
        });

        let parsed: DeviceAuthorizationRequestData = serde_json::from_value(stored).unwrap();

        assert_eq!(parsed.status, DeviceRequestStatus::Pending);
        assert_eq!(parsed.slow_down_seconds, 0);
        assert!(parsed.last_polled_at.is_none());
        assert!(parsed.approval.is_none());
        assert!(parsed.decided_at.is_none());
        assert!(parsed.device_authorization_oid.is_none());
    }
}
