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
    pub jwk: serde_json::Value,
    pub created_at: DateTime<Utc>,
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
}

#[derive(Debug, Clone)]
pub struct CreateKeyJwkInput {
    pub key_oid: KeyOid,
    pub algorithm: String,
    pub jwk: serde_json::Value,
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
    use super::{CreateKeyJwkInput, KeyJwk, KeyJwkOid, KeyOid};
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn key_jwk_oid_round_trips_through_uuid() {
        let raw = Uuid::new_v4();
        let oid = KeyJwkOid::from(raw);
        assert_eq!(Uuid::from(oid), raw);
    }

    #[test]
    fn key_jwk_oid_round_trips_through_json() {
        let oid = KeyJwkOid::from(Uuid::new_v4());
        let json = serde_json::to_string(&oid).unwrap();
        let decoded: KeyJwkOid = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn key_jwk_holds_algorithm_and_key_reference() {
        let key_oid = KeyOid::from(Uuid::new_v4());
        let jwk_json = json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "kid-1", "n": "...", "e": "AQAB"});

        let binding = KeyJwk {
            oid: KeyJwkOid::from(Uuid::new_v4()),
            key_oid,
            algorithm: "RS256".to_owned(),
            jwk: jwk_json.clone(),
            created_at: Utc::now(),
        };

        assert_eq!(binding.algorithm, "RS256");
        assert_eq!(Uuid::from(binding.key_oid), Uuid::from(key_oid));
        assert_eq!(binding.jwk, jwk_json);
    }

    #[test]
    fn create_key_jwk_input_builder() {
        let key_oid = KeyOid::from(Uuid::new_v4());
        let input = CreateKeyJwkInput {
            key_oid,
            algorithm: "PS256".to_owned(),
            jwk: json!({"kty": "RSA", "alg": "PS256", "use": "sig"}),
        };

        assert_eq!(input.algorithm, "PS256");
    }
}
