use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, EntityTrait};
use serde_json::Value;

use crate::database::{entity::setting, repository::setting::SettingRepositoryImpl};
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    setting::{
        DeviceAuthorizationSetting, DomainSetting, DynamicClientRegistrationSetting,
        InstallationFirstKeyOidSetting, InstallationFirstUserOidSetting,
        InstallationInitializedAtSetting, InstallationInitializedSetting, InstallationState,
        LoginDomainSetting, OrdinarySettingsProvider, OrdinarySettingsSnapshot,
        PasswordHashSetting, SettingDefinition,
        repository::{SettingRepository, SettingRepositoryError},
        runtime::RefreshableSetting,
    },
};

/// One typed snapshot of the ordinary setting table, shared by all consumers.
pub struct OrdinarySettings {
    db: DatabaseConnection,
    snapshot: RwLock<Arc<OrdinarySettingsSnapshot>>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl OrdinarySettings {
    pub async fn new(db: DatabaseConnection) -> Result<Self, AppError> {
        let snapshot = Self::load(&db, None).await?;
        Ok(Self {
            db,
            snapshot: RwLock::new(Arc::new(snapshot)),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    async fn load(
        db: &DatabaseConnection,
        previous: Option<&OrdinarySettingsSnapshot>,
    ) -> Result<OrdinarySettingsSnapshot, AppError> {
        let rows = setting::Entity::find().all(db).await.map_err(|error| {
            AppError::from_code(CommonErrorCode::InternalError).with_source(error)
        })?;
        let values: HashMap<_, _> = rows.into_iter().map(|row| (row.key, row.value)).collect();
        let repo = SettingRepositoryImpl::new(db.clone());

        let password_hash_options = read::<PasswordHashSetting>(
            &values,
            &repo,
            previous.map(|state| &state.password_hash_options),
        )
        .await?;
        let installation_initialized = read::<InstallationInitializedSetting>(
            &values,
            &repo,
            previous.map(|state| &state.installation.initialized),
        )
        .await?;
        let domain = read::<DomainSetting>(
            &values,
            &repo,
            previous.map(|state| &state.installation.domain),
        )
        .await?;
        let login_domain =
            read::<LoginDomainSetting>(&values, &repo, previous.map(|state| &state.login_domain))
                .await?;
        let first_user_oid = read::<InstallationFirstUserOidSetting>(
            &values,
            &repo,
            previous.map(|state| &state.installation.first_user_oid),
        )
        .await?;
        let first_key_oid = read::<InstallationFirstKeyOidSetting>(
            &values,
            &repo,
            previous.map(|state| &state.installation.first_key_oid),
        )
        .await?;
        let initialized_at = read::<InstallationInitializedAtSetting>(
            &values,
            &repo,
            previous.map(|state| &state.installation.initialized_at),
        )
        .await?;
        let dynamic_client_registration = read::<DynamicClientRegistrationSetting>(
            &values,
            &repo,
            previous.map(|state| &state.dynamic_client_registration),
        )
        .await?;
        let device_authorization = read::<DeviceAuthorizationSetting>(
            &values,
            &repo,
            previous.map(|state| &state.device_authorization),
        )
        .await?;
        let installation = InstallationState {
            initialized: installation_initialized,
            domain,
            first_user_oid,
            first_key_oid,
            initialized_at,
        };

        Ok(OrdinarySettingsSnapshot {
            password_hash_options,
            installation,
            login_domain,
            dynamic_client_registration,
            device_authorization,
        })
    }

    pub async fn refresh(&self) -> Result<(), AppError> {
        let _guard = self.refresh_lock.lock().await;
        let previous = self.snapshot();
        let next = Self::load(&self.db, Some(&previous)).await?;
        if previous.as_ref() != &next {
            let next = Arc::new(next);
            *self
                .snapshot
                .write()
                .unwrap_or_else(|error| error.into_inner()) = Arc::clone(&next);
            emit_changes(&previous, &next);
        }
        Ok(())
    }

    fn snapshot(&self) -> Arc<OrdinarySettingsSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    #[must_use]
    pub fn initialized(&self) -> bool {
        self.snapshot().installation.initialized
    }

    #[must_use]
    pub fn login_domain_value(&self) -> Option<String> {
        self.snapshot().login_domain.clone()
    }
}

pub(super) async fn read<S: SettingDefinition>(
    values: &HashMap<String, Value>,
    repo: &SettingRepositoryImpl,
    previous: Option<&S::Value>,
) -> Result<S::Value, AppError> {
    let Some(value) = values.get(S::KEY) else {
        return Ok(repo.upsert::<S>(&S::default_value()).await?.value);
    };
    let parsed = serde_json::from_value::<S::Value>(value.clone())
        .map_err(SettingRepositoryError::Deserialize)
        .and_then(|parsed| {
            S::validate(&parsed)
                .map_err(|error| SettingRepositoryError::Validation(error.message().to_owned()))?;
            Ok(parsed)
        });
    match (parsed, previous) {
        (Ok(value), _) => Ok(value),
        (Err(error), Some(previous)) => {
            tracing::warn!(key = S::KEY, error = %error, "failed to refresh setting");
            Ok(previous.clone())
        }
        (Err(error), None) => Err(error.into()),
    }
}

fn emit_changes(previous: &OrdinarySettingsSnapshot, next: &OrdinarySettingsSnapshot) {
    use identity_application::observability::{BusinessEvent, EventValue};
    macro_rules! changed {
        ($setting:ty, $($field:ident).+) => {
            if previous.$($field).+ != next.$($field).+ {
                identity_application::observability::event_sink().emit(
                    BusinessEvent::business("configuration.changed")
                        .outcome("applied")
                        .attribute("setting_key", EventValue::Text(<$setting>::KEY.to_owned())),
                );
            }
        };
    }
    changed!(PasswordHashSetting, password_hash_options);
    changed!(InstallationInitializedSetting, installation.initialized);
    changed!(DomainSetting, installation.domain);
    changed!(LoginDomainSetting, login_domain);
    changed!(InstallationFirstUserOidSetting, installation.first_user_oid);
    changed!(InstallationFirstKeyOidSetting, installation.first_key_oid);
    changed!(
        InstallationInitializedAtSetting,
        installation.initialized_at
    );
    changed!(
        DynamicClientRegistrationSetting,
        dynamic_client_registration
    );
    changed!(DeviceAuthorizationSetting, device_authorization);
}

#[async_trait]
impl RefreshableSetting for OrdinarySettings {
    fn key(&self) -> &'static str {
        "settings"
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await
    }
}

impl OrdinarySettingsProvider for OrdinarySettings {
    fn current_snapshot(&self) -> Arc<OrdinarySettingsSnapshot> {
        self.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn row<S: SettingDefinition>(id: i32, value: S::Value) -> setting::Model {
        setting::Model {
            id,
            oid: Uuid::new_v4(),
            key: S::KEY.to_owned(),
            value: serde_json::to_value(value).unwrap(),
            created_at: Utc::now().naive_utc(),
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn one_snapshot_refreshes_all_modules_and_keeps_last_valid_value() {
        let initial = vec![
            row::<PasswordHashSetting>(1, PasswordHashSetting::default_value()),
            row::<InstallationInitializedSetting>(
                2,
                InstallationInitializedSetting::default_value(),
            ),
            row::<DomainSetting>(3, DomainSetting::default_value()),
            row::<LoginDomainSetting>(4, LoginDomainSetting::default_value()),
            row::<InstallationFirstUserOidSetting>(
                5,
                InstallationFirstUserOidSetting::default_value(),
            ),
            row::<InstallationFirstKeyOidSetting>(
                6,
                InstallationFirstKeyOidSetting::default_value(),
            ),
            row::<InstallationInitializedAtSetting>(
                7,
                InstallationInitializedAtSetting::default_value(),
            ),
            row::<DynamicClientRegistrationSetting>(
                8,
                DynamicClientRegistrationSetting::default_value(),
            ),
            row::<DeviceAuthorizationSetting>(9, DeviceAuthorizationSetting::default_value()),
        ];
        let mut updated = initial.clone();
        updated[3].value = json!("https://login.example");
        updated[7].value = json!(true);
        updated[8].value = json!({
            "request_ttl_seconds": 0,
            "polling_interval_seconds": 5
        });
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([initial])
            .append_query_results([updated])
            .into_connection();

        let settings = OrdinarySettings::new(db).await.unwrap();
        settings.refresh().await.unwrap();

        assert_eq!(
            &settings.current_snapshot().login_domain,
            &Some("https://login.example".to_owned())
        );
        assert!(settings.current_snapshot().dynamic_client_registration);
        assert_eq!(
            settings
                .current_snapshot()
                .device_authorization
                .request_ttl_seconds,
            DeviceAuthorizationSetting::default_value().request_ttl_seconds
        );
    }
}
