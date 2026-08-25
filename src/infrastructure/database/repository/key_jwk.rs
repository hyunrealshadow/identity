use async_trait::async_trait;
use chrono::DateTime;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::database::entity::{key_jwk, key_jwk::Entity as KeyJwkEntity};
use identity_domain::key::{
    CreateKeyJwkInput, JwaSigningAlgorithm, JwkAlgorithm, KeyJwk, KeyJwkOid, KeyJwkRepository,
    KeyJwkRepositoryError, KeyOid, PublicJwk,
};

pub struct KeyJwkRepositoryImpl {
    db: DatabaseConnection,
}

impl KeyJwkRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn normalize_jwk_kid(mut jwk: PublicJwk, oid: Uuid) -> PublicJwk {
    jwk.set_key_id(oid.to_string());
    jwk
}

fn validate_jwk_algorithm(
    jwk: &PublicJwk,
    algorithm: JwkAlgorithm,
) -> Result<(), KeyJwkRepositoryError> {
    if let Some(jwk_algorithm) = jwk.algorithm()
        && jwk_algorithm != algorithm.as_str()
    {
        return Err(KeyJwkRepositoryError::InvalidPublicJwk(format!(
            "JWK algorithm {jwk_algorithm} does not match binding algorithm {algorithm}"
        )));
    }
    Ok(())
}

fn to_domain(model: key_jwk::Model) -> Result<KeyJwk, KeyJwkRepositoryError> {
    let created_at = DateTime::from_naive_utc_and_offset(model.created_at, chrono::Utc);
    let jwk = serde_json::from_value::<PublicJwk>(model.jwk)
        .map_err(|error| KeyJwkRepositoryError::InvalidPublicJwk(error.to_string()))?;
    let algorithm = model
        .algorithm
        .parse()
        .map_err(|_| KeyJwkRepositoryError::UnsupportedAlgorithm(model.algorithm.clone()))?;
    validate_jwk_algorithm(&jwk, algorithm)?;
    Ok(KeyJwk {
        oid: KeyJwkOid(model.oid),
        key_oid: KeyOid(model.key_oid),
        algorithm,
        jwk: normalize_jwk_kid(jwk, model.oid),
        created_at,
    })
}

#[async_trait]
impl KeyJwkRepository for KeyJwkRepositoryImpl {
    async fn create_batch(
        &self,
        inputs: Vec<CreateKeyJwkInput>,
    ) -> Result<Vec<KeyJwk>, KeyJwkRepositoryError> {
        if inputs.is_empty() {
            return Ok(vec![]);
        }

        let now = chrono::Utc::now();
        let models: Vec<key_jwk::ActiveModel> = inputs
            .into_iter()
            .map(|input| {
                let oid = Uuid::new_v4();
                validate_jwk_algorithm(&input.jwk, input.algorithm)?;
                let jwk = normalize_jwk_kid(input.jwk, oid);
                let jwk = serde_json::to_value(jwk)
                    .map_err(|error| KeyJwkRepositoryError::InvalidPublicJwk(error.to_string()))?;

                Ok(key_jwk::ActiveModel {
                    oid: Set(oid),
                    key_oid: Set(Uuid::from(input.key_oid)),
                    algorithm: Set(input.algorithm.to_string()),
                    jwk: Set(jwk),
                    created_at: Set(now.naive_utc()),
                    ..Default::default()
                })
            })
            .collect::<Result<_, _>>()?;

        let results = KeyJwkEntity::insert_many(models)
            .exec_with_returning(&self.db)
            .await
            .map_err(|e| KeyJwkRepositoryError::CreateBatchFailed(Box::new(e)))?;

        Ok(results
            .into_iter()
            .map(to_domain)
            .collect::<Result<_, _>>()?)
    }

    async fn list_active(&self) -> Result<Vec<KeyJwk>, KeyJwkRepositoryError> {
        use crate::database::entity::key;
        KeyJwkEntity::find()
            .inner_join(key::Entity)
            .filter(key::Column::RevokedAt.is_null())
            .filter(key::Column::ExpiresAt.gt(chrono::Utc::now()))
            .all(&self.db)
            .await
            .map_err(|e| KeyJwkRepositoryError::ListActiveFailed(Box::new(e)))?
            .into_iter()
            .map(to_domain)
            .collect()
    }

    async fn find_active_by_key_oid_and_algorithm(
        &self,
        key_oid: KeyOid,
        algorithm: JwaSigningAlgorithm,
    ) -> Result<Option<KeyJwk>, KeyJwkRepositoryError> {
        use crate::database::entity::key;

        KeyJwkEntity::find()
            .inner_join(key::Entity)
            .filter(key::Column::RevokedAt.is_null())
            .filter(key::Column::ExpiresAt.gt(chrono::Utc::now()))
            .filter(key_jwk::Column::KeyOid.eq(Uuid::from(key_oid)))
            .filter(key_jwk::Column::Algorithm.eq(algorithm.as_str()))
            .one(&self.db)
            .await
            .map_err(|e| KeyJwkRepositoryError::ListByKeyFailed(Box::new(e)))?
            .map(to_domain)
            .transpose()
    }

    async fn delete_by_key_oid(&self, key_oid: KeyOid) -> Result<(), KeyJwkRepositoryError> {
        key_jwk::Entity::delete_many()
            .filter(key_jwk::Column::KeyOid.eq(Uuid::from(key_oid)))
            .exec(&self.db)
            .await
            .map_err(|e| KeyJwkRepositoryError::DeleteByKeyFailed(Box::new(e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyJwkRepositoryImpl, normalize_jwk_kid};
    use crate::database::entity::key_jwk;
    use chrono::Utc;
    use identity_domain::key::{JwaSigningAlgorithm, KeyJwkRepository, KeyOid, PublicJwk};
    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase};
    use serde_json::json;
    use uuid::Uuid;

    fn rsa_public_jwk(alg: &str, kid: impl Into<String>) -> PublicJwk {
        PublicJwk::Rsa {
            key_use: Some("sig".to_owned()),
            alg: Some(alg.to_owned()),
            kid: Some(kid.into()),
            n: "modulus".to_owned(),
            e: "AQAB".to_owned(),
            x5c: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    #[test]
    fn key_jwk_repository_sets_kid_to_binding_oid() {
        let binding_oid = Uuid::new_v4();
        let normalized = normalize_jwk_kid(
            rsa_public_jwk("RS256", Uuid::new_v4().to_string()),
            binding_oid,
        );

        assert_eq!(normalized.key_id(), Some(binding_oid.to_string().as_str()));
    }

    #[test]
    fn key_jwk_repository_rewrites_legacy_kid_to_binding_oid() {
        let binding_oid = Uuid::new_v4();
        let binding = super::to_domain(key_jwk::Model {
            id: 1,
            oid: binding_oid,
            key_oid: Uuid::new_v4(),
            algorithm: "RS256".to_owned(),
            jwk: json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": Uuid::new_v4().to_string(),
                "n": "modulus",
                "e": "AQAB"
            }),
            created_at: Utc::now().naive_utc(),
            updated_at: None,
        })
        .unwrap();

        assert_eq!(binding.jwk.key_id(), Some(binding_oid.to_string().as_str()));
    }

    #[test]
    fn key_jwk_repository_rejects_algorithm_mismatch() {
        let error = super::to_domain(key_jwk::Model {
            id: 1,
            oid: Uuid::new_v4(),
            key_oid: Uuid::new_v4(),
            algorithm: "ES256".to_owned(),
            jwk: json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "modulus",
                "e": "AQAB"
            }),
            created_at: Utc::now().naive_utc(),
            updated_at: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("does not match"));
    }

    #[tokio::test]
    async fn find_active_key_jwk_by_key_oid_and_algorithm_returns_binding() {
        let key_oid = Uuid::new_v4();
        let binding_oid = Uuid::new_v4();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[key_jwk::Model {
                id: 1,
                oid: binding_oid,
                key_oid,
                algorithm: "RS256".to_owned(),
                jwk: json!({
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": Uuid::new_v4().to_string(),
                    "n": "modulus",
                    "e": "AQAB"
                }),
                created_at: Utc::now().naive_utc(),
                updated_at: None,
            }
            .into_mock_row()]])
            .into_connection();
        let repo = KeyJwkRepositoryImpl::new(db);

        let binding = repo
            .find_active_by_key_oid_and_algorithm(KeyOid::from(key_oid), JwaSigningAlgorithm::Rs256)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(Uuid::from(binding.oid), binding_oid);
        assert_eq!(binding.jwk.key_id(), Some(binding_oid.to_string().as_str()));
    }
}
