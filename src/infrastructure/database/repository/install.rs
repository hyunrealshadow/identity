use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use rand::RngExt;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set, TransactionTrait,
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
        openid_connect::{
            GrantType, OpenIdConnectCredentialData, ResponseType, SubjectType,
            TokenEndpointAuthMethod,
        },
        setting::{
            ConsentUrlSetting, LoginUrlSetting,
            installation::{
                InstallationDomainSetting, InstallationFirstKeyOidSetting,
                InstallationFirstUserOidSetting, InstallationInitializedAtSetting,
                InstallationInitializedSetting, InstallationState,
            },
            model::SettingDefinition,
        },
        user::CredentialType,
    },
    infrastructure::{
        crypto::key::generate_all_jwks_for_key,
        database::{
            entity::{
                client, client_open_id_connect, client_open_id_connect_credential, client_platform,
                client_scope, key, key_jwk, scope, setting, user, user_credential,
            },
            repository::{
                openid_connect_credential::serialize_data as serialize_credential_data,
                shared::encode_nonnullable_expiry,
            },
        },
    },
};

pub struct InstallPersistenceImpl {
    db: DatabaseConnection,
}

// Deliberately distinct from the process-lifetime startup guard lock.
const INSTALL_TRANSACTION_LOCK_ID: i64 = 841_463_791_178_241_512;

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
        let client_oid = input.client_id;
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

        acquire_install_transaction_lock(&txn).await?;
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
            r#type: Set(CredentialType::Password.to_string()),
            data: Set(password_json),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        let created_client = client::ActiveModel {
            oid: Set(client_oid),
            protocol: Set("openid_connect".to_owned()),
            name: Set("Identity Account".to_owned()),
            names: Set(None),
            description: Set(Some(
                "Built-in account and session management application".to_owned(),
            )),
            built_in: Set(true),
            created_at: Set(now.naive_utc()),
            updated_at: Set(Some(now.naive_utc())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        let callback_url = built_in_callback_url(&input.application_url)?;
        client_open_id_connect::ActiveModel {
            client_id: Set(created_client.id),
            post_logout_redirect_uris: Set(Some(serde_json::json!([input
                .application_url
                .as_str()]))),
            response_types: Set(Some(serde_json::json!([ResponseType::Code]))),
            grant_types: Set(Some(serde_json::json!([
                GrantType::AuthorizationCode.as_str(),
                GrantType::RefreshToken.as_str()
            ]))),
            subject_type: Set(Some(SubjectType::Public.to_string())),
            token_endpoint_auth_method: Set(Some(
                TokenEndpointAuthMethod::ClientSecretBasic.to_string(),
            )),
            settings: Set(serde_json::json!({
                "skip_consent": true,
                "allow_public_client_flow": false
            })),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        client_platform::ActiveModel {
            client_id: Set(created_client.id),
            platform: Set("web".to_owned()),
            redirect_uris: Set(Some(serde_json::json!([callback_url.as_str()]))),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        let assigned_scope_names = [
            "openid",
            "profile",
            "email",
            "offline_access",
            "account",
            "session",
            "password.change",
        ];
        let assigned_scopes = scope::Entity::find()
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .filter(scope::Column::Name.is_in(assigned_scope_names))
            .all(&txn)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        if assigned_scopes.len() != assigned_scope_names.len() {
            return Err(AppError::from_code(CommonErrorCode::InternalError));
        }
        client_scope::Entity::insert_many(assigned_scopes.into_iter().map(|scope| {
            client_scope::ActiveModel {
                client_id: Set(created_client.id),
                scope_id: Set(scope.id),
                created_at: Set(now.into()),
                ..Default::default()
            }
        }))
        .exec(&txn)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

        let serialized_credential =
            serialize_credential_data(OpenIdConnectCredentialData::ClientSecret {
                secret: input.client_secret,
            });
        client_open_id_connect_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            client_id: Set(created_client.id),
            r#type: Set(serialized_credential.type_),
            data: Set(serialized_credential.data),
            hint: Set(serialized_credential.hint),
            expires_at: Set((now + input.client_secret_lifetime).into()),
            revoked_at: Set(None),
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
        upsert_setting(
            &txn,
            LoginUrlSetting::KEY,
            serde_json::json!(input.application_url.join("login").map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?),
        )
        .await?;
        upsert_setting(
            &txn,
            ConsentUrlSetting::KEY,
            serde_json::json!(input.application_url.join("consent").map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?),
        )
        .await?;

        txn.commit().await.map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;

        Ok(installation_state)
    }
}

async fn acquire_install_transaction_lock<C>(db: &C) -> Result<(), AppError>
where
    C: ConnectionTrait,
{
    let statement = format!("SELECT pg_advisory_xact_lock({INSTALL_TRANSACTION_LOCK_ID})");
    db.execute_unprepared(&statement)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;
    Ok(())
}

fn built_in_callback_url(application_url: &url::Url) -> Result<url::Url, AppError> {
    application_url
        .join("callback")
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))
}

async fn installation_state_exists<C>(db: &C) -> Result<bool, AppError>
where
    C: ConnectionTrait,
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
    C: ConnectionTrait,
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
    C: ConnectionTrait,
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

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::{
        INSTALL_TRANSACTION_LOCK_ID, acquire_install_transaction_lock, built_in_callback_url,
    };

    #[test]
    fn built_in_client_uses_top_level_callback_route() {
        let application_url = url::Url::parse("https://identity.example/").unwrap();

        assert_eq!(
            built_in_callback_url(&application_url).unwrap().as_str(),
            "https://identity.example/callback"
        );
    }

    #[tokio::test]
    async fn install_lock_is_transaction_scoped() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_exec_results([MockExecResult::default()])
            .into_connection();

        acquire_install_transaction_lock(&db).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::one(Statement::from_string(
                DbBackend::Postgres,
                format!("SELECT pg_advisory_xact_lock({INSTALL_TRANSACTION_LOCK_ID})"),
            ))]
        );
    }
}
