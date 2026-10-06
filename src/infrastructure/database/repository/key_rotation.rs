use std::error::Error;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    key::rotation::{KEY_LIFETIME, KEY_ROTATION_AGE, KeyRotationRepository, RotationMaterial},
};
use identity_domain::key::{Key, KeyOid, KeyType};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set, TransactionTrait, sea_query::Expr,
};
use serde_json::to_value;
use uuid::Uuid;

use super::key::to_domain;
use crate::database::{
    entity::{key, key_jwk},
    query::advisory_transaction_lock,
};

pub struct KeyRotationRepositoryImpl {
    db: DatabaseConnection,
}

impl KeyRotationRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn internal(error: impl Error + Send + Sync + 'static) -> AppError {
    AppError::from_code(CommonErrorCode::InternalError).with_source(error)
}

#[async_trait]
impl KeyRotationRepository for KeyRotationRepositoryImpl {
    async fn list_due(&self, now: DateTime<Utc>) -> Result<Vec<Key>, AppError> {
        key::Entity::find()
            .filter(key::Column::Type.is_in([
                KeyType::Asymmetric.to_string(),
                KeyType::Symmetric.to_string(),
            ]))
            .filter(key::Column::RevokedAt.is_null())
            .filter(key::Column::RotatedAt.is_null())
            .filter(key::Column::CreatedAt.lte(now - KEY_ROTATION_AGE))
            .all(&self.db)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|model| to_domain(model).map_err(internal))
            .collect()
    }

    async fn rotate_if_due(
        &self,
        previous_oid: KeyOid,
        material: RotationMaterial,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let txn = self.db.begin().await.map_err(internal)?;
        txn.execute(&advisory_transaction_lock(684395120247316902_i64))
            .await
            .map_err(internal)?;

        let previous = key::Entity::find()
            .filter(key::Column::Oid.eq(Uuid::from(previous_oid)))
            .one(&txn)
            .await
            .map_err(internal)?;
        let Some(previous) = previous else {
            return Ok(false);
        };
        if (previous.r#type != KeyType::Asymmetric.to_string()
            && previous.r#type != KeyType::Symmetric.to_string())
            || material.data.key_type().to_string() != previous.r#type
            || (previous.r#type == KeyType::Symmetric.to_string() && !material.jwks.is_empty())
            || previous.revoked_at.is_some()
            || previous.rotated_at.is_some()
            || previous.created_at > now - KEY_ROTATION_AGE
        {
            return Ok(false);
        }

        let next_oid = Uuid::new_v4();
        let next = key::ActiveModel {
            oid: Set(next_oid),
            r#type: Set(previous.r#type.clone()),
            data: Set(to_value(material.data).map_err(internal)?),
            expires_at: Set((now + KEY_LIFETIME).into()),
            revoked_at: Set(None),
            rotated_from_oid: Set(Some(Uuid::from(previous_oid))),
            rotated_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(None),
            ..Default::default()
        };
        next.insert(&txn).await.map_err(internal)?;

        for generated in material.jwks {
            let binding_oid = Uuid::new_v4();
            let mut jwk = generated.jwk;
            jwk.set_key_id(binding_oid.to_string());
            key_jwk::ActiveModel {
                oid: Set(binding_oid),
                key_oid: Set(next_oid),
                algorithm: Set(generated.algorithm.as_str().to_owned()),
                jwk: Set(to_value(jwk).map_err(internal)?),
                created_at: Set(now.into()),
                updated_at: Set(None),
                ..Default::default()
            }
            .insert(&txn)
            .await
            .map_err(internal)?;
        }

        // Asymmetric predecessors remain available for signature verification.
        // Symmetric predecessors remain loaded for decryption even after expiry.
        let retiring_expiry = previous.expires_at.min((now + Duration::days(30)).into());
        key::Entity::update_many()
            .col_expr(
                key::Column::RotatedAt,
                Expr::value(Some(now.fixed_offset())),
            )
            .col_expr(key::Column::ExpiresAt, Expr::value(retiring_expiry))
            .col_expr(
                key::Column::UpdatedAt,
                Expr::value(Some(now.fixed_offset())),
            )
            .filter(key::Column::Id.eq(previous.id))
            .exec(&txn)
            .await
            .map_err(internal)?;
        txn.commit().await.map_err(internal)?;
        Ok(true)
    }
}
