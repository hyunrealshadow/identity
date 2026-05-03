use async_trait::async_trait;
use chrono::DateTime;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::database::entity::{key_jwk, key_jwk::Entity as KeyJwkEntity};
use identity_domain::key::{
    CreateKeyJwkInput, KeyJwk, KeyJwkOid, KeyJwkRepository, KeyJwkRepositoryError, KeyOid,
};

pub struct KeyJwkRepositoryImpl {
    db: DatabaseConnection,
}

impl KeyJwkRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn normalize_jwk_kid(mut jwk: serde_json::Value, oid: Uuid) -> serde_json::Value {
    if let Some(object) = jwk.as_object_mut() {
        object.insert("kid".to_owned(), serde_json::json!(oid.to_string()));
    }
    jwk
}

fn to_domain(model: key_jwk::Model) -> Result<KeyJwk, KeyJwkRepositoryError> {
    let created_at = DateTime::from_naive_utc_and_offset(model.created_at, chrono::Utc);
    Ok(KeyJwk {
        oid: KeyJwkOid(model.oid),
        key_oid: KeyOid(model.key_oid),
        algorithm: model.algorithm,
        jwk: normalize_jwk_kid(model.jwk, model.oid),
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
                key_jwk::ActiveModel {
                    oid: Set(oid),
                    key_oid: Set(Uuid::from(input.key_oid)),
                    algorithm: Set(input.algorithm),
                    jwk: Set(normalize_jwk_kid(input.jwk, oid)),
                    created_at: Set(now.naive_utc()),
                    ..Default::default()
                }
            })
            .collect();

        let results = KeyJwkEntity::insert_many(models)
            .exec_with_returning(&self.db)
            .await
            .map_err(KeyJwkRepositoryError::CreateBatchFailed)?;

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
            .all(&self.db)
            .await
            .map_err(KeyJwkRepositoryError::ListActiveFailed)?
            .into_iter()
            .map(to_domain)
            .collect()
    }

    async fn find_active_by_key_oid_and_algorithm(
        &self,
        key_oid: KeyOid,
        algorithm: &str,
    ) -> Result<Option<KeyJwk>, KeyJwkRepositoryError> {
        use crate::database::entity::key;

        KeyJwkEntity::find()
            .inner_join(key::Entity)
            .filter(key::Column::RevokedAt.is_null())
            .filter(key_jwk::Column::KeyOid.eq(Uuid::from(key_oid)))
            .filter(key_jwk::Column::Algorithm.eq(algorithm))
            .one(&self.db)
            .await
            .map_err(KeyJwkRepositoryError::ListByKeyFailed)?
            .map(to_domain)
            .transpose()
    }

    async fn delete_by_key_oid(&self, key_oid: KeyOid) -> Result<(), KeyJwkRepositoryError> {
        key_jwk::Entity::delete_many()
            .filter(key_jwk::Column::KeyOid.eq(Uuid::from(key_oid)))
            .exec(&self.db)
            .await
            .map_err(KeyJwkRepositoryError::DeleteByKeyFailed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyJwkRepositoryImpl, normalize_jwk_kid};
    use crate::database::entity::key_jwk;
    use chrono::Utc;
    use identity_domain::key::{KeyJwkRepository, KeyOid};
    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn key_jwk_repository_sets_kid_to_binding_oid() {
        let binding_oid = Uuid::new_v4();
        let normalized = normalize_jwk_kid(
            json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": Uuid::new_v4().to_string()
            }),
            binding_oid,
        );

        assert_eq!(normalized["kid"], json!(binding_oid.to_string()));
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
                "kid": Uuid::new_v4().to_string()
            }),
            created_at: Utc::now().naive_utc(),
            updated_at: None,
        })
        .unwrap();

        assert_eq!(binding.jwk["kid"], json!(binding_oid.to_string()));
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
                    "kid": Uuid::new_v4().to_string()
                }),
                created_at: Utc::now().naive_utc(),
                updated_at: None,
            }
            .into_mock_row()]])
            .into_connection();
        let repo = KeyJwkRepositoryImpl::new(db);

        let binding = repo
            .find_active_by_key_oid_and_algorithm(KeyOid::from(key_oid), "RS256")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(Uuid::from(binding.oid), binding_oid);
        assert_eq!(binding.jwk["kid"], json!(binding_oid.to_string()));
    }
}
