use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use std::{fmt, str::FromStr};

use super::{JwaEncryptionAlgorithm, JwaSigningAlgorithm, KeyOid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwkAlgorithm {
    Signing(JwaSigningAlgorithm),
    Encryption(JwaEncryptionAlgorithm),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid JWK algorithm")]
pub struct ParseJwkAlgorithmError;

impl JwkAlgorithm {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signing(value) => value.as_str(),
            Self::Encryption(value) => value.as_str(),
        }
    }
}

impl fmt::Display for JwkAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<JwaSigningAlgorithm> for JwkAlgorithm {
    fn from(value: JwaSigningAlgorithm) -> Self {
        Self::Signing(value)
    }
}

impl From<JwaEncryptionAlgorithm> for JwkAlgorithm {
    fn from(value: JwaEncryptionAlgorithm) -> Self {
        Self::Encryption(value)
    }
}

impl FromStr for JwkAlgorithm {
    type Err = ParseJwkAlgorithmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse::<JwaSigningAlgorithm>()
            .map(Self::Signing)
            .or_else(|_| {
                value
                    .parse::<JwaEncryptionAlgorithm>()
                    .map(Self::Encryption)
            })
            .map_err(|_| ParseJwkAlgorithmError)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
    derive_more::Into,
)]
pub struct KeyJwkOid(pub uuid::Uuid);

#[derive(Debug, Clone)]
pub struct KeyJwk {
    pub oid: KeyJwkOid,
    pub key_oid: KeyOid,
    pub algorithm: JwkAlgorithm,
    pub jwk: PublicJwk,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum PublicJwk {
    #[serde(rename = "RSA")]
    Rsa {
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        key_use: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<String>,
        n: String,
        e: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        x5c: Option<Vec<String>>,
        #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
        x5t: Option<String>,
        #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
        x5t_s256: Option<String>,
    },
    #[serde(rename = "EC")]
    Ec {
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        key_use: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<String>,
        crv: String,
        x: String,
        y: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        x5c: Option<Vec<String>>,
        #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
        x5t: Option<String>,
        #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
        x5t_s256: Option<String>,
    },
    #[serde(rename = "OKP")]
    Okp {
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        key_use: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<String>,
        crv: String,
        x: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        x5c: Option<Vec<String>>,
        #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
        x5t: Option<String>,
        #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
        x5t_s256: Option<String>,
    },
}

impl PublicJwk {
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        match self {
            Self::Rsa { alg, .. } | Self::Ec { alg, .. } | Self::Okp { alg, .. } => alg.as_deref(),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        match self {
            Self::Rsa { kid, .. } | Self::Ec { kid, .. } | Self::Okp { kid, .. } => kid.as_deref(),
        }
    }

    pub fn set_key_id(&mut self, value: impl Into<String>) {
        let value = Some(value.into());
        match self {
            Self::Rsa { kid, .. } | Self::Ec { kid, .. } | Self::Okp { kid, .. } => *kid = value,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyJwkRepositoryError {
    #[error("failed to create jwk bindings")]
    CreateBatchFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to list jwk bindings by key")]
    ListByKeyFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to list active jwk bindings")]
    ListActiveFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to delete jwk bindings")]
    DeleteByKeyFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("invalid public jwk: {0}")]
    InvalidPublicJwk(String),

    #[error("unsupported JWK signing algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

#[derive(Debug, Clone)]
pub struct CreateKeyJwkInput {
    pub key_oid: KeyOid,
    pub algorithm: JwkAlgorithm,
    pub jwk: PublicJwk,
}

#[async_trait::async_trait]
pub trait KeyJwkRepository: Send + Sync {
    async fn create_batch(
        &self,
        inputs: Vec<CreateKeyJwkInput>,
    ) -> Result<Vec<KeyJwk>, KeyJwkRepositoryError>;

    async fn list_active(&self) -> Result<Vec<KeyJwk>, KeyJwkRepositoryError>;

    async fn find_active_by_key_oid_and_algorithm(
        &self,
        key_oid: KeyOid,
        algorithm: JwaSigningAlgorithm,
    ) -> Result<Option<KeyJwk>, KeyJwkRepositoryError>;

    async fn delete_by_key_oid(&self, key_oid: KeyOid) -> Result<(), KeyJwkRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::PublicJwk;

    #[test]
    fn okp_public_jwk_preserves_certificate_parameters() {
        let value = serde_json::json!({
            "kty": "OKP",
            "use": "sig",
            "alg": "EdDSA",
            "kid": "kid-ed",
            "crv": "Ed25519",
            "x": "public-key",
            "x5c": ["certificate"],
            "x5t": "sha1-thumbprint",
            "x5t#S256": "sha256-thumbprint"
        });

        let jwk: PublicJwk = serde_json::from_value(value).unwrap();
        let serialized = serde_json::to_value(jwk).unwrap();

        assert_eq!(serialized["x5c"], serde_json::json!(["certificate"]));
        assert_eq!(serialized["x5t"], serde_json::json!("sha1-thumbprint"));
        assert_eq!(
            serialized["x5t#S256"],
            serde_json::json!("sha256-thumbprint")
        );
    }
}
