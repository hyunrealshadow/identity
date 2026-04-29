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

fn to_domain(model: key_jwk::Model) -> Result<KeyJwk, KeyJwkRepositoryError> {
    let created_at = DateTime::from_naive_utc_and_offset(model.created_at, chrono::Utc);
    Ok(KeyJwk {
        oid: KeyJwkOid(model.oid),
        key_oid: KeyOid(model.key_oid),
        algorithm: model.algorithm,
        jwk: model.jwk,
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
            .map(|input| key_jwk::ActiveModel {
                oid: Set(Uuid::new_v4()),
                key_oid: Set(Uuid::from(input.key_oid)),
                algorithm: Set(input.algorithm),
                jwk: Set(input.jwk),
                created_at: Set(now.naive_utc()),
                ..Default::default()
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

    async fn delete_by_key_oid(&self, key_oid: KeyOid) -> Result<(), KeyJwkRepositoryError> {
        key_jwk::Entity::delete_many()
            .filter(key_jwk::Column::KeyOid.eq(Uuid::from(key_oid)))
            .exec(&self.db)
            .await
            .map_err(KeyJwkRepositoryError::DeleteByKeyFailed)?;
        Ok(())
    }
}
