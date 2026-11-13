use std::error::Error;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    key::{
        asymmetric::{GeneratedKeyJwk, KeyJwkGenerator},
        rotation::{KEY_LIFETIME, KEY_ROTATION_AGE, KeyRotationRepository, RotationMaterial},
    },
};
use identity_domain::key::{JwaSigningAlgorithm, Key, KeyData, KeyOid, KeyType};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, Set, TransactionTrait, sea_query::Expr,
};
use serde_json::to_value;
use uuid::Uuid;

use super::key::to_domain;
use crate::crypto::key_jwk::KeyJwkGeneratorImpl;
use crate::database::{
    entity::{
        key,
        key::{Column as KeyColumn, Entity as KeyEntity},
        key_jwk,
    },
    query::advisory_transaction_lock,
};

/// Advisory lock serializing every key rotation and revocation.
pub(crate) const KEY_ROTATION_LOCK: i64 = 684395120247316902;

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
        KeyEntity::find()
            .filter(KeyColumn::Type.is_in([
                KeyType::Asymmetric.to_string(),
                KeyType::Symmetric.to_string(),
            ]))
            .filter(KeyColumn::RevokedAt.is_null())
            .filter(KeyColumn::RotatedAt.is_null())
            .filter(KeyColumn::CreatedAt.lte(now - KEY_ROTATION_AGE))
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
        txn.execute(&advisory_transaction_lock(KEY_ROTATION_LOCK))
            .await
            .map_err(internal)?;

        let previous = KeyEntity::find()
            .filter(KeyColumn::Oid.eq(Uuid::from(previous_oid)))
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

        insert_successor(&txn, &previous, material, now)
            .await
            .map_err(internal)?;
        txn.commit().await.map_err(internal)?;
        Ok(true)
    }
}

/// Store `material` as the successor of `previous` and retire `previous`, on
/// the caller's transaction. The caller holds the rotation lock and has
/// checked that `previous` is still in use.
pub(crate) async fn insert_successor<C: ConnectionTrait>(
    txn: &C,
    previous: &key::Model,
    material: RotationMaterial,
    now: DateTime<Utc>,
) -> Result<Uuid, DbErr> {
    // The successor signs with the algorithms its predecessor published.
    let published = key_jwk::Entity::find()
        .filter(key_jwk::Column::KeyOid.eq(previous.oid))
        .all(txn)
        .await?
        .into_iter()
        .filter_map(|binding| binding.algorithm.parse::<JwaSigningAlgorithm>().ok())
        .collect::<Vec<_>>();
    let jwks = match (&material.data, published.is_empty()) {
        (KeyData::Asymmetric(data), false) => KeyJwkGeneratorImpl
            .generate_for(
                &data.private_key,
                "pending",
                data.certificate.as_deref(),
                &published,
            )
            .map_err(|error| DbErr::Custom(error.to_string()))?,
        _ => material.jwks,
    };
    let next_oid = insert_key(
        txn,
        &previous.r#type,
        material.data,
        jwks,
        Some(previous.oid),
        now,
    )
    .await?;

    // Asymmetric predecessors remain available for signature verification.
    // Symmetric predecessors remain loaded for decryption even after expiry.
    let retiring_expiry = previous.expires_at.min((now + Duration::days(30)).into());
    KeyEntity::update_many()
        .col_expr(KeyColumn::RotatedAt, Expr::value(Some(now.fixed_offset())))
        .col_expr(KeyColumn::ExpiresAt, Expr::value(retiring_expiry))
        .col_expr(KeyColumn::UpdatedAt, Expr::value(Some(now.fixed_offset())))
        .filter(KeyColumn::Id.eq(previous.id))
        .exec(txn)
        .await?;
    Ok(next_oid)
}

/// Store one key and its JWK bindings, each binding with its own `kid`.
pub(crate) async fn insert_key<C: ConnectionTrait>(
    txn: &C,
    key_type: &str,
    data: KeyData,
    jwks: Vec<GeneratedKeyJwk>,
    rotated_from: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<Uuid, DbErr> {
    let oid = Uuid::new_v4();
    let data = to_value(data).map_err(|error| DbErr::Custom(error.to_string()))?;
    key::ActiveModel {
        oid: Set(oid),
        r#type: Set(key_type.to_owned()),
        data: Set(data),
        expires_at: Set((now + KEY_LIFETIME).into()),
        revoked_at: Set(None),
        rotated_from_oid: Set(rotated_from),
        rotated_at: Set(None),
        created_at: Set(now.into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(txn)
    .await?;
    for generated in jwks {
        let binding_oid = Uuid::new_v4();
        let mut jwk = generated.jwk;
        jwk.set_key_id(identity_domain::openid_connect::identifier::key_id(
            binding_oid,
        ));
        let jwk = to_value(jwk).map_err(|error| DbErr::Custom(error.to_string()))?;
        key_jwk::ActiveModel {
            oid: Set(binding_oid),
            key_oid: Set(oid),
            algorithm: Set(generated.algorithm.as_str().to_owned()),
            jwk: Set(jwk),
            created_at: Set(now.into()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(txn)
        .await?;
    }
    Ok(oid)
}
