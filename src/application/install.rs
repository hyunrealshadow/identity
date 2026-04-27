use std::sync::Arc;

use base64::Engine as _;
use chrono::Utc;
use rand::RngCore;
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
        setting::runtime::{RefreshableSettingProvider, SettingProvider},
    },
    domain::{
        auth::password::{PasswordHashSetting, PasswordHasher},
        key::{
            AsymmetricKeyAlgorithm, KeyData, SymmetricKeyAlgorithm, SymmetricKeyData,
            generator::AsymmetricKeyGenerator,
        },
        setting::{
            installation::{InstallationSetting, InstallationState},
            model::SettingDefinition,
        },
        user::model::Password,
    },
    infrastructure::{
        crypto::certificate::generate_self_signed_certificate,
        database::{
            entity::{setting, user, user_credential},
            repository::shared::encode_nonnullable_expiry,
        },
    },
};

#[derive(Debug, Clone)]
pub struct InstallInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub domain: String,
    pub key_algorithm: AsymmetricKeyAlgorithm,
}

pub struct InstallService {
    pub db: DatabaseConnection,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub password_hash_options: Arc<dyn SettingProvider<PasswordHashSetting>>,
    pub installation_setting: Arc<dyn RefreshableSettingProvider<InstallationSetting>>,
    pub key_generator: Arc<dyn AsymmetricKeyGenerator>,
}

impl InstallService {
    pub fn is_initialized(&self) -> bool {
        self.installation_setting.current_value().initialized
    }

    pub async fn install(&self, input: InstallInput) -> Result<InstallationState, AppError> {
        if self.is_initialized() {
            return Err(AppError::from_code(InstallErrorCode::AlreadyInitialized));
        }

        let username = normalize_required(&input.username, "username")?;
        let email = normalize_email(&input.email)?;
        let password = normalize_required(&input.password, "password")?;
        let domain = normalize_domain(&input.domain)?;

        input
            .key_algorithm
            .validate()
            .map_err(|_| AppError::from_code(InstallErrorCode::AlgorithmInvalid))?;

        let hash_options = self.password_hash_options.current_value();
        let password = self
            .password_hasher
            .hash(&password, hash_options.as_ref())?;
        let mut key_data =
            self.key_generator
                .generate(&crate::domain::key::generator::AsymmetricKeySpec {
                    algorithm: input.key_algorithm.clone(),
                })?;
        let certificate =
            generate_self_signed_certificate(&key_data.private_key, &domain, &input.key_algorithm)?;
        key_data.certificate = Some(certificate);

        let installation_state = self
            .persist_installation(username, email, password, domain, key_data)
            .await?;

        self.installation_setting.refresh_value().await?;
        Ok(installation_state)
    }

    async fn persist_installation(
        &self,
        username: String,
        email: String,
        password: Password,
        domain: String,
        key_data: crate::domain::key::AsymmetricKeyData,
    ) -> Result<InstallationState, AppError> {
        let now = Utc::now();
        let user_oid = Uuid::new_v4();
        let key_oid = Uuid::new_v4();
        let normalized_username = crate::domain::user::normalization::normalize_username(&username)
            .ok_or_else(|| AppError::from_code(InstallErrorCode::UsernameRequired))?;
        let normalized_email = crate::domain::user::normalization::normalize_email(&email)
            .map_err(|_| AppError::from_code(InstallErrorCode::EmailInvalid))?;
        let password_json = serde_json::to_value(&password).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;
        let key_json = serde_json::to_value(crate::domain::key::KeyData::Asymmetric(key_data))
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;

        let installation_state = InstallationState {
            initialized: true,
            domain: Some(domain.clone()),
            first_user_oid: Some(user_oid),
            first_key_oid: Some(key_oid),
            initialized_at: Some(now),
        };

        let state_json = serde_json::to_value(&installation_state).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;

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
            email: Set(email),
            email_normalized: Set(normalized_email),
            name: Set(username),
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

        crate::infrastructure::database::entity::key::ActiveModel {
            oid: Set(key_oid),
            r#type: Set(crate::domain::key::KeyType::Asymmetric.to_string()),
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

        // Create an initial symmetric key for data protection (encrypting login IDs etc.)
        let mut sym_key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sym_key_bytes);
        let sym_key_b64 = base64::engine::general_purpose::STANDARD.encode(sym_key_bytes);
        let sym_key_json = serde_json::to_value(KeyData::Symmetric(SymmetricKeyData {
            key: sym_key_b64,
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        }))
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
        crate::infrastructure::database::entity::key::ActiveModel {
            oid: Set(Uuid::new_v4()),
            r#type: Set(crate::domain::key::KeyType::Symmetric.to_string()),
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

        upsert_installation_state(&txn, state_json).await?;

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
        .filter(setting::Column::Key.eq(InstallationSetting::KEY))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    let Some(state) = state else {
        return Ok(false);
    };

    let value: InstallationState = serde_json::from_value(state.value)
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    Ok(value.initialized)
}

async fn upsert_installation_state<C>(db: &C, value: Value) -> Result<(), AppError>
where
    C: sea_orm::ConnectionTrait,
{
    let now = Utc::now().naive_utc();
    if let Some(existing) = setting::Entity::find()
        .filter(setting::Column::Key.eq(InstallationSetting::KEY))
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
            key: Set(InstallationSetting::KEY.to_owned()),
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

fn normalize_required(value: &str, field: &'static str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        let code = match field {
            "username" => InstallErrorCode::UsernameRequired,
            "email" => InstallErrorCode::EmailRequired,
            "password" => InstallErrorCode::PasswordRequired,
            "domain" => InstallErrorCode::DomainRequired,
            _ => InstallErrorCode::UsernameRequired,
        };
        return Err(AppError::from_code(code));
    }

    Ok(value.to_owned())
}

fn normalize_domain(domain: &str) -> Result<String, AppError> {
    let domain = normalize_required(domain, "domain")?.to_lowercase();
    // If the domain contains a scheme (e.g. "https://localhost:5150"), skip
    // the dot-presence check since it is a full URL rather than a bare hostname.
    let is_url = domain.contains("://");
    if domain.contains(' ') || (!is_url && !domain.contains('.')) {
        return Err(AppError::from_code(InstallErrorCode::DomainInvalid));
    }

    Ok(domain)
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    crate::domain::user::normalization::normalize_email(email).map_err(|error| match error {
        crate::domain::user::normalization::EmailNormalizationError::Empty => {
            AppError::from_code(InstallErrorCode::EmailRequired)
        }
        crate::domain::user::normalization::EmailNormalizationError::InvalidFormat
        | crate::domain::user::normalization::EmailNormalizationError::InvalidDomain => {
            AppError::from_code(InstallErrorCode::EmailInvalid)
        }
    })
}
