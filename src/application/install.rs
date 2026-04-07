use std::sync::Arc;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    application::{
        error::{AppError, codes::common::CommonErrorCode},
        setting::runtime::{RefreshableSettingProvider, SettingProvider},
    },
    domain::{
        auth::password::{PasswordHashSetting, PasswordHasher},
        key::{generator::AsymmetricKeyGenerator, model::AsymmetricKeyAlgorithm},
        setting::{
            installation::{InstallationSetting, InstallationState},
            model::SettingDefinition,
        },
        user::model::Password,
    },
    infrastructure::{
        crypto::certificate::generate_self_signed_certificate,
        database::entity::{setting, user, user_credential},
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
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
                .with_param("message", "system already initialized"));
        }

        let username = normalize_required(&input.username, "username")?;
        let email = normalize_email(&input.email)?;
        let password = normalize_required(&input.password, "password")?;
        let domain = normalize_domain(&input.domain)?;

        input.key_algorithm.validate().map_err(|error| {
            AppError::from_code(CommonErrorCode::InvalidRequest).with_param("message", error)
        })?;

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
        key_data: crate::domain::key::model::AsymmetricKeyData,
    ) -> Result<InstallationState, AppError> {
        let now = Utc::now();
        let user_oid = Uuid::new_v4();
        let key_oid = Uuid::new_v4();
        let normalized_username = username.to_lowercase();
        let normalized_email = email.to_lowercase();
        let password_json = serde_json::to_value(&password).map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;
        let key_json =
            serde_json::to_value(crate::domain::key::model::KeyData::Asymmetric(key_data))
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
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
                .with_param("message", "system already initialized"));
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
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
                .with_param("message", "username already exists"));
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
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
                .with_param("message", "email already exists"));
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
            r#type: Set(crate::domain::key::model::KeyType::Asymmetric.to_string()),
            data: Set(key_json),
            expires_at: Set(None),
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
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
            .with_param("message", format!("{field} is required")));
    }

    Ok(value.to_owned())
}

fn normalize_domain(domain: &str) -> Result<String, AppError> {
    let domain = normalize_required(domain, "domain")?.to_lowercase();
    if domain.contains(' ') || !domain.contains('.') {
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
            .with_param("message", "domain is invalid"));
    }

    Ok(domain)
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    let email = normalize_required(email, "email")?.to_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.') {
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest)
            .with_param("message", "email is invalid"));
    }

    Ok(email)
}
