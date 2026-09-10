//! Manual PII marking.
//!
//! Values are only protected when the developer explicitly wraps them in
//! [`Pii`] (redact or HMAC-pseudonymize) or [`Secret`] (never recorded).
//! Formatting goes through the single policy installed at startup so console,
//! OTLP logs, audit events and span attributes observe the same rules before
//! any output layer sees a string.

use std::{fmt, sync::OnceLock};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Public marker that a field may be emitted as a keyed pseudonym.
pub const REDACTED: &str = "[REDACTED]";

const HMAC_PREFIX: &str = "hmac";

/// HMAC-SHA256 key and version used for pseudonymization.
#[derive(Debug)]
pub struct PiiPolicy {
    key: Vec<u8>,
    key_version: String,
}

impl PiiPolicy {
    #[must_use]
    pub fn new(key: Vec<u8>, key_version: impl Into<String>) -> Self {
        Self {
            key,
            key_version: key_version.into(),
        }
    }

    /// Stable pseudonym for one field purpose. The purpose is part of the MAC
    /// input and of the output so values from different fields cannot be
    /// conflated.
    #[must_use]
    pub fn pseudonymize(&self, purpose: &str, value: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(purpose.as_bytes());
        mac.update(b"\0");
        mac.update(value.as_bytes());
        let digest = mac.finalize().into_bytes();
        format!(
            "{HMAC_PREFIX}:{}:{purpose}:{}",
            self.key_version,
            hex::encode(digest)
        )
    }
}

static POLICY: OnceLock<Option<PiiPolicy>> = OnceLock::new();

/// Install the process-wide PII policy. Later calls are ignored, matching the
/// once-per-process tracing initialization.
pub(crate) fn install(policy: Option<PiiPolicy>) {
    let _ = POLICY.set(policy);
}

fn active_policy() -> Option<&'static PiiPolicy> {
    POLICY.get().and_then(Option::as_ref)
}

/// A field that must not be emitted verbatim.
///
/// [`Pii::redacted`] always renders [`REDACTED`].
/// [`Pii::pseudonymized`] renders a keyed HMAC when the process has an HMAC
/// key, otherwise it falls back to [`REDACTED`] - never to the raw value.
#[derive(Clone, Copy)]
pub struct Pii<T> {
    value: T,
    purpose: Option<&'static str>,
}

impl<T> Pii<T> {
    #[must_use]
    pub const fn redacted(value: T) -> Self {
        Self {
            value,
            purpose: None,
        }
    }

    /// Mark a field for value-correlation (`user_oid`, `session_oid`, ...).
    /// Purpose strings must be stable, low-cardinality literals.
    #[must_use]
    pub const fn pseudonymized(purpose: &'static str, value: T) -> Self {
        Self {
            value,
            purpose: Some(purpose),
        }
    }

    /// Access the raw value for business logic. Rendering never uses this.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }
}

impl<T: fmt::Display> Pii<T> {
    fn render_with(&self, policy: Option<&PiiPolicy>) -> String {
        match (self.purpose, policy) {
            (Some(purpose), Some(policy)) => policy.pseudonymize(purpose, &self.value.to_string()),
            _ => REDACTED.to_owned(),
        }
    }

    fn render(&self) -> String {
        self.render_with(active_policy())
    }
}

impl<T: fmt::Display> fmt::Display for Pii<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

impl<T: fmt::Display> fmt::Debug for Pii<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

/// Credentials and other values that must never appear in telemetry, at any
/// level, with or without a PII policy. Rendering is always [`REDACTED`].
#[derive(Clone, Copy)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Access the raw value for business logic.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::{Pii, PiiPolicy, REDACTED, Secret};

    #[test]
    fn secret_is_always_redacted() {
        let secret = Secret::new("s3cr3t");
        assert_eq!(secret.to_string(), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(secret.expose(), &"s3cr3t");
    }

    #[test]
    fn redacted_pii_stays_redacted_with_policy_installed() {
        let pii = Pii::redacted("alice@example.com");
        assert_eq!(pii.to_string(), REDACTED);
        assert_eq!(format!("{pii:?}"), REDACTED);
    }

    #[test]
    fn pseudonymized_pii_is_stable_and_purpose_scoped() {
        let policy = PiiPolicy::new(b"unit-test-key".to_vec(), "v1");
        let first = policy.pseudonymize("user_oid", "11111111-1111-1111-1111-111111111111");
        let second = policy.pseudonymize("user_oid", "11111111-1111-1111-1111-111111111111");
        let other_purpose =
            policy.pseudonymize("session_oid", "11111111-1111-1111-1111-111111111111");

        assert_eq!(first, second);
        assert_ne!(first, other_purpose);
        assert!(first.starts_with("hmac:v1:user_oid:"));
        assert!(!first.contains("11111111"));
    }

    #[test]
    fn missing_policy_never_leaks_raw_value() {
        let value = "11111111-1111-1111-1111-111111111111";
        let pii = Pii::pseudonymized("user_oid", value);

        assert_eq!(pii.render_with(None), REDACTED);
        let pseudonym = pii.render_with(Some(&PiiPolicy::new(b"key".to_vec(), "v1")));
        assert!(pseudonym.starts_with("hmac:v1:user_oid:"));
        assert!(!pseudonym.contains(value));
    }
}
