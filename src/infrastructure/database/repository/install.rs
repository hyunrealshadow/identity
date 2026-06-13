use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use rand::RngExt;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    application::{
        error::{
            AppError,
            codes::{common::CommonErrorCode, install::InstallErrorCode},
        },
        install::{InstallPersistence, InstallPersistenceInput},
    },
    domain::{
        key::{KeyData, KeyType, SymmetricKeyAlgorithm, SymmetricKeyData},
        setting::{
            installation::{
                InstallationDomainSetting, InstallationFirstKeyOidSetting,
                InstallationFirstUserOidSetting, InstallationInitializedAtSetting,
                InstallationInitializedSetting, InstallationState,
            },
            model::SettingDefinition,
        },
    },
    infrastructure::{
        crypto::key::generate_all_jwks_for_key,
        database::{
            entity::{key, key_jwk, setting, user, user_credential},
            repository::shared::encode_nonnullable_expiry,
        },
    },
};

pub struct InstallPersistenceImpl {
    db: DatabaseConnection,
}

impl InstallPersistenceImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl InstallPersistence for InstallPersistenceImpl {
    async fn persist_installation(
        &self,
        input: InstallPersistenceInput,
    ) -> Result<InstallationState, AppError> {
        let now = Utc::now();
        let user_oid = Uuid::new_v4();
        let key_oid = Uuid::new_v4();
        let normalized_username =
            identity_domain::user::normalization::normalize_username(&input.username)
                .ok_or_else(|| AppError::from_code(InstallErrorCode::UsernameRequired))?;
        let normalized_email = identity_domain::user::normalization::normalize_email(&input.email)
            .map_err(|_| AppError::from_code(InstallErrorCode::EmailInvalid))?;
        let password_json = serde_json::to_value(&input.password).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;
        let key_json =
            serde_json::to_value(KeyData::Asymmetric(input.key_data.clone())).map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;

        let installation_state = InstallationState {
            initialized: true,
            domain: Some(input.domain.clone()),
            first_user_oid: Some(user_oid),
            first_key_oid: Some(key_oid),
            initialized_at: Some(now),
        };

        let txn = self.db.begin().await.map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;

        if installation_state_exists(&txn).await? {
            return Err(AppError::from_code(InstallErrorCode::AlreadyInitialized));
        }

        if user::Entity::find()
            .filter(user::Column::NameNormalized.eq(&normalized_username))
            .one(&txn)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?
            .is_some()
        {
            return Err(AppError::from_code(InstallErrorCode::UsernameExists));
        }

        if user::Entity::find()
            .filter(user::Column::EmailNormalized.eq(&normalized_email))
            .one(&txn)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?
            .is_some()
        {
            return Err(AppError::from_code(InstallErrorCode::EmailExists));
        }

        let created_user = user::ActiveModel {
            oid: Set(user_oid),
            email: Set(input.email),
            email_normalized: Set(normalized_email),
            name: Set(input.username),
            name_normalized: Set(normalized_username),
            email_verified: Set(true),
            failed_attempts: Set(0),
            enabled: Set(true),
            locked: Set(false),
            locked_until: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(created_user.id),
            r#type: Set("password".to_owned()),
            data: Set(password_json),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        key::ActiveModel {
            oid: Set(key_oid),
            r#type: Set(KeyType::Asymmetric.to_string()),
            data: Set(key_json),
            expires_at: Set(encode_nonnullable_expiry(None)),
            revoked_at: Set(None),
            created_at: Set(now.naive_utc()),
            updated_at: Set(Some(now.naive_utc())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        let jwks = generate_all_jwks_for_key(
            &input.key_data.private_key,
            &key_oid.to_string(),
            input.key_data.certificate.as_deref(),
        )
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
        let jwk_models = jwks
            .into_iter()
            .map(|(algorithm, jwk)| {
                serde_json::to_value(jwk).map(|jwk| key_jwk::ActiveModel {
                    oid: Set(Uuid::new_v4()),
                    key_oid: Set(key_oid),
                    algorithm: Set(algorithm),
                    jwk: Set(jwk),
                    created_at: Set(now.naive_utc()),
                    updated_at: Set(Some(now.naive_utc())),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        key_jwk::Entity::insert_many(jwk_models)
            .exec(&txn)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;

        let mut sym_key_bytes = [0u8; 32];
        rand::rng().fill(&mut sym_key_bytes[..]);
        let sym_key_b64 = base64::engine::general_purpose::STANDARD.encode(sym_key_bytes);
        let sym_key_json = serde_json::to_value(KeyData::Symmetric(SymmetricKeyData {
            key: sym_key_b64,
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        }))
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
        key::ActiveModel {
            oid: Set(Uuid::new_v4()),
            r#type: Set(KeyType::Symmetric.to_string()),
            data: Set(sym_key_json),
            expires_at: Set(encode_nonnullable_expiry(None)),
            revoked_at: Set(None),
            created_at: Set(now.naive_utc()),
            updated_at: Set(Some(now.naive_utc())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        upsert_installation_state(&txn, &installation_state).await?;

        txn.commit().await.map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;

        Ok(installation_state)
    }
}

async fn installation_state_exists<C>(db: &C) -> Result<bool, AppError>
where
    C: sea_orm::ConnectionTrait,
{
    let state = setting::Entity::find()
        .filter(setting::Column::Key.eq(InstallationInitializedSetting::KEY))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    let Some(state) = state else {
        return Ok(false);
    };

    let value: bool = serde_json::from_value(state.value)
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    Ok(value)
}

async fn upsert_installation_state<C>(db: &C, state: &InstallationState) -> Result<(), AppError>
where
    C: sea_orm::ConnectionTrait,
{
    upsert_setting(
        db,
        InstallationInitializedSetting::KEY,
        serde_json::to_value(state.initialized).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?,
    )
    .await?;
    upsert_setting(
        db,
        InstallationDomainSetting::KEY,
        serde_json::to_value(&state.domain).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?,
    )
    .await?;
    upsert_setting(
        db,
        InstallationFirstUserOidSetting::KEY,
        serde_json::to_value(state.first_user_oid).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?,
    )
    .await?;
    upsert_setting(
        db,
        InstallationFirstKeyOidSetting::KEY,
        serde_json::to_value(state.first_key_oid).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?,
    )
    .await?;
    upsert_setting(
        db,
        InstallationInitializedAtSetting::KEY,
        serde_json::to_value(state.initialized_at).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?,
    )
    .await?;

    Ok(())
}

async fn upsert_setting<C>(db: &C, key: &str, value: Value) -> Result<(), AppError>
where
    C: sea_orm::ConnectionTrait,
{
    let now = Utc::now().naive_utc();
    if let Some(existing) = setting::Entity::find()
        .filter(setting::Column::Key.eq(key))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?
    {
        let mut active: setting::ActiveModel = existing.into();
        active.value = Set(value);
        active.updated_at = Set(Some(now));
        active.update(db).await.map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;
    } else {
        setting::ActiveModel {
            oid: Set(Uuid::new_v4()),
            key: Set(key.to_owned()),
            value: Set(value),
            created_at: Set(now),
            updated_at: Set(Some(now)),
            ..Default::default()
        }
        .insert(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    }

    Ok(())
}
