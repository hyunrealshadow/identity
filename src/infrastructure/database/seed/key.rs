use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::infrastructure::database::entity::key;
use crate::infrastructure::database::repository::key::KeyRepositoryImpl;
use crate::infrastructure::database::seed::Seed;
use crate::{
    application::{
        error::{AppError, codes::common::CommonErrorCode},
        key::asymmetric::{AsymmetricKeyService, GenerateAsymmetricKeyInput},
    },
    domain::key::model::AsymmetricKeyAlgorithm,
    infrastructure::crypto::key::AsymmetricKeyGeneratorImpl,
};

pub struct Es256KeySeed;

#[async_trait]
impl Seed for Es256KeySeed {
    fn name(&self) -> &'static str {
        "key"
    }

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        if let Some(model) = key::Entity::find()
            .filter(key::Column::Type.eq("asymmetric"))
            .filter(key::Column::RevokedAt.is_null())
            .one(db)
            .await
            .map_err(|_| AppError::from_code(CommonErrorCode::InternalError))?
        {
            tracing::info!(seed = self.name(), key_oid = %model.oid, "existing key reused");
            return Ok(());
        }

        let service = AsymmetricKeyService {
            repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
            generator: Arc::new(AsymmetricKeyGeneratorImpl),
        };

        let key = service
            .generate_and_store(GenerateAsymmetricKeyInput {
                algorithm: AsymmetricKeyAlgorithm::EcdsaP256,
                expires_at: None,
                certificate: None,
            })
            .await?;

        tracing::info!(seed = self.name(), key_oid = %key.oid, "new key created");
        Ok(())
    }
}
