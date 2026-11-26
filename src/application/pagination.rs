//! Shared application-layer Relay pagination, fingerprinting, and protected cursor helpers.

use std::fmt::{self, Write as _};

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::data_protection::DataProtector;
use identity_domain::data_protection::DataProtectionError;
pub use identity_domain::pagination::{
    DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, PageDirection, PaginationError, RawPageArgs, ValidatedPage,
    finalize_keyset_page, validate_page_arguments,
};

/// Failures produced when protecting or decoding structured application cursors.
#[derive(Debug)]
pub enum CursorCodecError {
    EmptyToken,
    Serialize(serde_json::Error),
    Protect(DataProtectionError),
    Unprotect(DataProtectionError),
    Deserialize(serde_json::Error),
}

impl fmt::Display for CursorCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyToken => f.write_str("cursor token is empty"),
            Self::Serialize(err) => write!(f, "failed to serialize cursor payload: {err}"),
            Self::Protect(err) => write!(f, "failed to protect cursor payload: {err}"),
            Self::Unprotect(err) => write!(f, "failed to unprotect cursor token: {err}"),
            Self::Deserialize(err) => write!(f, "failed to deserialize cursor payload: {err}"),
        }
    }
}

impl std::error::Error for CursorCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EmptyToken => None,
            Self::Serialize(err) | Self::Deserialize(err) => Some(err),
            Self::Protect(err) | Self::Unprotect(err) => Some(err),
        }
    }
}

/// Encode raw bytes as lowercase hexadecimal SHA-256 digest.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Hash a serializable filter/order structure with SHA-256 into lowercase hex.
pub fn cursor_fingerprint<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_vec(value)?;
    Ok(sha256_hex(&encoded))
}

/// Convenience wrapper for infallible filter/order structures hashed via JSON.
#[must_use]
pub fn json_filter_fingerprint<T: Serialize>(value: &T) -> String {
    cursor_fingerprint(value).unwrap_or_default()
}

/// Encrypt and authenticate a single JSON cursor payload.
pub async fn protect_json_cursor<T: Serialize>(
    protector: &dyn DataProtector,
    purpose: &str,
    payload: &T,
) -> Result<String, CursorCodecError> {
    let bytes = serde_json::to_vec(payload).map_err(CursorCodecError::Serialize)?;
    protector
        .protect(purpose, &bytes)
        .await
        .map_err(CursorCodecError::Protect)
}

/// Encrypt and authenticate a page of JSON cursor payloads in a single batch.
pub async fn protect_json_cursors<T: Serialize>(
    protector: &dyn DataProtector,
    purpose: &str,
    payloads: &[T],
) -> Result<Vec<String>, CursorCodecError> {
    if payloads.is_empty() {
        return Ok(Vec::new());
    }
    let mut plaintexts = Vec::with_capacity(payloads.len());
    for payload in payloads {
        plaintexts.push(serde_json::to_vec(payload).map_err(CursorCodecError::Serialize)?);
    }
    protector
        .protect_many(purpose, &plaintexts)
        .await
        .map_err(CursorCodecError::Protect)
}

/// Authenticate, decrypt, and deserialize a JSON cursor payload.
pub async fn unprotect_json_cursor<T: DeserializeOwned>(
    protector: &dyn DataProtector,
    purpose: &str,
    token: &str,
) -> Result<T, CursorCodecError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(CursorCodecError::EmptyToken);
    }
    let bytes = protector
        .unprotect(purpose, trimmed)
        .await
        .map_err(CursorCodecError::Unprotect)?;
    serde_json::from_slice(&bytes).map_err(CursorCodecError::Deserialize)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use serde::{Deserialize, Serialize};

    use super::*;

    struct PrefixProtector;

    #[async_trait]
    impl DataProtector for PrefixProtector {
        async fn protect(
            &self,
            purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            let body = std::str::from_utf8(plaintext).unwrap();
            Ok(format!("{purpose}:{body}"))
        }

        async fn unprotect(
            &self,
            purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            let prefix = format!("{purpose}:");
            let rest = token
                .strip_prefix(&prefix)
                .ok_or(DataProtectionError::InvalidProtectedPayload)?;
            Ok(rest.as_bytes().to_vec())
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SampleCursor {
        filter: String,
        id: i64,
    }

    #[test]
    fn cursor_fingerprint_is_deterministic_and_sensitive_to_changes() {
        let a = cursor_fingerprint(&("alpha", 1_u8)).unwrap();
        let b = cursor_fingerprint(&("alpha", 1_u8)).unwrap();
        let c = cursor_fingerprint(&("alpha", 2_u8)).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[tokio::test]
    async fn protect_and_unprotect_json_cursors_batch_round_trips() {
        let protector = PrefixProtector;
        let payloads = vec![
            SampleCursor {
                filter: "f1".to_owned(),
                id: 10,
            },
            SampleCursor {
                filter: "f1".to_owned(),
                id: 20,
            },
        ];

        assert!(
            protect_json_cursors::<SampleCursor>(&protector, "cursor:test", &[])
                .await
                .unwrap()
                .is_empty()
        );

        let tokens = protect_json_cursors(&protector, "cursor:test", &payloads)
            .await
            .unwrap();
        assert_eq!(tokens.len(), 2);

        let first: SampleCursor = unprotect_json_cursor(&protector, "cursor:test", &tokens[0])
            .await
            .unwrap();
        assert_eq!(first, payloads[0]);

        let wrong_purpose =
            unprotect_json_cursor::<SampleCursor>(&protector, "cursor:other", &tokens[1]).await;
        assert!(matches!(wrong_purpose, Err(CursorCodecError::Unprotect(_))));

        let empty = unprotect_json_cursor::<SampleCursor>(&protector, "cursor:test", "   ").await;
        assert!(matches!(empty, Err(CursorCodecError::EmptyToken)));
    }
}
