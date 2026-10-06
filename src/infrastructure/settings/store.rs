use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use identity_application::{
    error::AppError,
    observability::{BusinessEvent, EventValue, event_sink},
    setting::{SettingRegistry, SettingsSnapshot, SettingsSource, runtime::RefreshableSetting},
};
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;

use crate::database::entity::setting;

/// The registered settings of the `setting` table, decoded into one snapshot
/// shared by all consumers.
pub struct SettingsStore {
    db: DatabaseConnection,
    registry: SettingRegistry,
    snapshot: RwLock<Arc<SettingsSnapshot>>,
    refresh_lock: Mutex<()>,
}

impl SettingsStore {
    pub async fn new(db: DatabaseConnection, registry: SettingRegistry) -> Result<Self, AppError> {
        let snapshot = load(&db, &registry, None).await?;
        Ok(Self {
            db,
            registry,
            snapshot: RwLock::new(Arc::new(snapshot)),
            refresh_lock: Mutex::new(()),
        })
    }

    pub async fn refresh(&self) -> Result<(), AppError> {
        let _guard = self.refresh_lock.lock().await;
        let previous = self.snapshot();
        let next = load(&self.db, &self.registry, Some(&previous)).await?;
        if *previous != next {
            emit_changes(&previous, &next);
            *self
                .snapshot
                .write()
                .unwrap_or_else(|error| error.into_inner()) = Arc::new(next);
        }
        Ok(())
    }
}

/// Reads the whole table in one query. Loading never writes: defaults are
/// stored once at startup by the setting defaults seed, and a row that is
/// still missing reads as its declared default.
async fn load(
    db: &DatabaseConnection,
    registry: &SettingRegistry,
    previous: Option<&SettingsSnapshot>,
) -> Result<SettingsSnapshot, AppError> {
    let rows = setting::Entity::find()
        .all(db)
        .await
        .map_err(AppError::internal)?;
    let raw: HashMap<_, _> = rows.into_iter().map(|row| (row.key, row.value)).collect();
    Ok(registry.resolve(&raw, previous)?)
}

fn emit_changes(previous: &SettingsSnapshot, next: &SettingsSnapshot) {
    for key in previous.changed_keys(next) {
        event_sink().emit(
            BusinessEvent::business("configuration.changed")
                .outcome("applied")
                .attribute("setting_key", EventValue::Text(key.to_owned())),
        );
    }
}

#[async_trait]
impl RefreshableSetting for SettingsStore {
    fn key(&self) -> &'static str {
        "settings"
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await
    }
}

impl SettingsSource for SettingsStore {
    fn snapshot(&self) -> Arc<SettingsSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use identity_application::setting::{
        DeviceAuthorizationSettings, DomainSetting, LoginDomainSetting, OpenIdConnectSettings,
        SettingDefinition,
    };
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::{Value, json, to_value};
    use uuid::Uuid;

    use super::*;

    fn row<S: SettingDefinition>(id: i32, value: Value) -> setting::Model {
        row_at(id, S::KEY, value)
    }

    fn row_at(id: i32, key: &str, value: Value) -> setting::Model {
        setting::Model {
            id,
            oid: Uuid::new_v4(),
            key: key.to_owned(),
            value,
            created_at: Utc::now().into(),
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn one_snapshot_refreshes_all_settings_and_keeps_last_valid_value() {
        let registry = SettingRegistry::default()
            .register::<DomainSetting>()
            .register::<LoginDomainSetting>()
            .register_section::<OpenIdConnectSettings>();
        let initial = vec![
            row::<DomainSetting>(1, json!(null)),
            row::<LoginDomainSetting>(2, json!(null)),
            row_at(
                3,
                "openid_connect.dynamic_registration.enabled",
                json!(false),
            ),
            row_at(
                4,
                "openid_connect.device_authorization",
                to_value(DeviceAuthorizationSettings::default()).unwrap(),
            ),
        ];
        let mut updated = initial.clone();
        updated[1].value = json!("https://login.example");
        updated[2].value = json!(true);
        updated[3].value = json!({
            "request_ttl_seconds": 0,
            "polling_interval_seconds": 5
        });
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([initial])
            .append_query_results([updated])
            .into_connection();

        let settings = SettingsStore::new(db, registry).await.unwrap();
        settings.refresh().await.unwrap();

        let snapshot = settings.snapshot();
        assert_eq!(
            snapshot.get::<LoginDomainSetting>().as_deref(),
            Some("https://login.example")
        );
        assert!(
            snapshot
                .section::<OpenIdConnectSettings>()
                .dynamic_registration
                .enabled
        );
        assert_eq!(
            snapshot
                .section::<OpenIdConnectSettings>()
                .device_authorization,
            DeviceAuthorizationSettings::default()
        );
    }
}
