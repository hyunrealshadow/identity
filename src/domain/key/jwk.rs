use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::KeyOid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyJwkOid(pub Uuid);

impl From<Uuid> for KeyJwkOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<KeyJwkOid> for Uuid {
    fn from(value: KeyJwkOid) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct KeyJwk {
    pub oid: KeyJwkOid,
    pub key_oid: KeyOid,
    pub algorithm: String,
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
    CreateBatchFailed(#[source] sea_orm::DbErr),

    #[error("failed to list jwk bindings by key")]
    ListByKeyFailed(#[source] sea_orm::DbErr),

    #[error("failed to list active jwk bindings")]
    ListActiveFailed(#[source] sea_orm::DbErr),

    #[error("failed to delete jwk bindings")]
    DeleteByKeyFailed(#[source] sea_orm::DbErr),

    #[error("invalid public jwk: {0}")]
    InvalidPublicJwk(String),
}

#[derive(Debug, Clone)]
pub struct CreateKeyJwkInput {
    pub key_oid: KeyOid,
    pub algorithm: String,
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
        algorithm: &str,
    ) -> Result<Option<KeyJwk>, KeyJwkRepositoryError>;

    async fn delete_by_key_oid(&self, key_oid: KeyOid) -> Result<(), KeyJwkRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::{CreateKeyJwkInput, KeyJwk, KeyJwkOid, KeyOid, PublicJwk};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn key_jwk_oid_round_trips_through_uuid() {
        let raw = Uuid::new_v4();
        let oid = KeyJwkOid::from(raw);
        assert_eq!(Uuid::from(oid), raw);
    }

    #[test]
    fn key_jwk_holds_algorithm_and_key_reference() {
        let key_oid = KeyOid::from(Uuid::new_v4());
        let jwk = PublicJwk::Rsa {
            key_use: Some("sig".to_owned()),
            alg: Some("RS256".to_owned()),
            kid: Some("kid-1".to_owned()),
            n: "modulus".to_owned(),
            e: "AQAB".to_owned(),
            x5c: None,
            x5t: None,
            x5t_s256: None,
        };

        let binding = KeyJwk {
            oid: KeyJwkOid::from(Uuid::new_v4()),
            key_oid,
            algorithm: "RS256".to_owned(),
            jwk: jwk.clone(),
            created_at: Utc::now(),
        };

        assert_eq!(binding.algorithm, "RS256");
        assert_eq!(Uuid::from(binding.key_oid), Uuid::from(key_oid));
        assert_eq!(binding.jwk, jwk);
    }

    #[test]
    fn create_key_jwk_input_builder() {
        let key_oid = KeyOid::from(Uuid::new_v4());
        let input = CreateKeyJwkInput {
            key_oid,
            algorithm: "PS256".to_owned(),
            jwk: PublicJwk::Rsa {
                key_use: Some("sig".to_owned()),
                alg: Some("PS256".to_owned()),
                kid: None,
                n: "modulus".to_owned(),
                e: "AQAB".to_owned(),
                x5c: None,
                x5t: None,
                x5t_s256: None,
            },
        };

        assert_eq!(input.algorithm, "PS256");
        assert_eq!(input.jwk.algorithm(), Some("PS256"));
    }

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
