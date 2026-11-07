//! Public keys an administrator registers for `private_key_jwt`.
//!
//! Reading key material is a cryptographic concern, so it sits behind this
//! port; the infrastructure implementation shares the JOSE and X.509 handling
//! the server uses for its own keys.

use chrono::{DateTime, Utc};
use identity_domain::key::PublicJwk;

/// A validated key in the form the credential stores it. Client assertion
/// verification accepts either form directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyMaterial {
    Pem(String),
    Jwk(PublicJwk),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPublicKey {
    pub material: PublicKeyMaterial,
    /// Identifies the key without exposing it: a JWK's `kid` or RFC 7638
    /// thumbprint, or the SHA-256 of a PEM key's SubjectPublicKeyInfo.
    pub hint: String,
    /// `notAfter` of a certificate; bare keys carry no expiry.
    pub certificate_expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicKeyError {
    #[error("the key is empty or too long")]
    Length,
    #[error("private key material was supplied")]
    Private,
    #[error("the key cannot verify client assertions")]
    Unusable,
    #[error("the certificate has already expired")]
    CertificateExpired,
}

/// Reads a PEM public key, a PEM certificate or a single public JWK. A key is
/// accepted only when a client assertion verifier can be built from it.
pub trait ClientPublicKeyReader: Send + Sync {
    fn read(&self, input: &str) -> Result<ReadPublicKey, PublicKeyError>;
}
