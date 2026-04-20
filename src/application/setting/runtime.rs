use std::{
    marker::PhantomData,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

use crate::{
    application::error::AppError,
    domain::setting::{
        model::{SettingDefinition, SettingEntry},
        repository::SettingRepository,
    },
};

pub trait SettingProvider<S>: Send + Sync
where
    S: SettingDefinition,
{
    fn current_value(&self) -> Arc<S::Value>;
}

pub trait RefreshableSettingProvider<S>: SettingProvider<S> + RefreshableSetting
where
    S: SettingDefinition,
{
}

impl<S, T> RefreshableSettingProvider<S> for T
where
    S: SettingDefinition,
    T: SettingProvider<S> + RefreshableSetting + ?Sized,
{
}

impl<S, T> SettingProvider<S> for Arc<T>
where
    S: SettingDefinition,
    T: SettingProvider<S> + ?Sized,
{
    fn current_value(&self) -> Arc<S::Value> {
        self.as_ref().current_value()
    }
}

pub struct CachedSetting<S, R>
where
    S: SettingDefinition,
{
    repo: R,
    value: RwLock<Arc<S::Value>>,
    _marker: PhantomData<S>,
}

impl<S, R> CachedSetting<S, R>
where
    S: SettingDefinition,
    R: SettingRepository,
{
    pub async fn new(repo: R) -> Result<Self, AppError> {
        let initial = Self::load_or_create(&repo).await?;

        Ok(Self {
            repo,
            value: RwLock::new(Arc::new(initial.value)),
            _marker: PhantomData,
        })
    }

    pub async fn refresh(&self) -> Result<SettingEntry<S::Value>, AppError> {
        let entry = Self::load_or_create(&self.repo).await?;
        self.replace_current(&entry.value);
        Ok(entry)
    }

    pub async fn set(&self, value: S::Value) -> Result<SettingEntry<S::Value>, AppError> {
        let entry = self.repo.upsert::<S>(&value).await?;
        self.replace_current(&entry.value);
        Ok(entry)
    }

    async fn load_or_create(repo: &R) -> Result<SettingEntry<S::Value>, AppError> {
        match repo.get::<S>().await? {
            Some(entry) => Ok(entry),
            None => Ok(repo.upsert::<S>(&S::default_value()).await?),
        }
    }

    fn replace_current(&self, value: &S::Value) {
        let mut current = self.write_current();

        if current.as_ref() != value {
            *current = Arc::new(value.clone());
        }
    }

    fn read_current(&self) -> RwLockReadGuard<'_, Arc<S::Value>> {
        self.value.read().unwrap_or_else(|error| error.into_inner())
    }

    fn write_current(&self) -> RwLockWriteGuard<'_, Arc<S::Value>> {
        self.value
            .write()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl<S, R> SettingProvider<S> for CachedSetting<S, R>
where
    S: SettingDefinition,
    R: SettingRepository,
{
    fn current_value(&self) -> Arc<S::Value> {
        self.read_current().clone()
    }
}

#[async_trait]
pub trait RefreshableSetting: Send + Sync {
    fn key(&self) -> &'static str;

    async fn refresh_value(&self) -> Result<(), AppError>;
}

#[async_trait]
impl<S, R> RefreshableSetting for CachedSetting<S, R>
where
    S: SettingDefinition,
    R: SettingRepository,
{
    fn key(&self) -> &'static str {
        S::KEY
    }

    async fn refresh_value(&self) -> Result<(), AppError> {
        self.refresh().await.map(|_| ())
    }
}

pub struct SettingsRefresher {
    interval: Duration,
    settings: Vec<Arc<dyn RefreshableSetting>>,
}

impl SettingsRefresher {
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            settings: Vec::new(),
        }
    }

    pub fn register<T>(&mut self, setting: Arc<T>)
    where
        T: RefreshableSetting + 'static,
    {
        self.settings.push(setting);
    }

    #[must_use]
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            if self.settings.is_empty() {
                return;
            }

            tracing::info!(
                refresh_interval_secs = self.interval.as_secs_f64(),
                setting_count = self.settings.len(),
                "starting settings refresh task"
            );

            let mut ticker = time::interval(self.interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            ticker.tick().await;

            loop {
                ticker.tick().await;

                for setting in &self.settings {
                    if let Err(error) = setting.refresh_value().await {
                        tracing::warn!(key = setting.key(), error = %error, "failed to refresh setting");
                    }
                }
            }
        })
    }

    pub fn spawn_detached(self) {
        let _ = self.spawn();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, RwLock,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use chrono::Utc;
    use serde_json::Value;
    use uuid::Uuid;

    use super::{CachedSetting, RefreshableSetting, SettingProvider, SettingsRefresher};
    use crate::{
        application::error::AppError,
        domain::setting::{
            model::{SettingDefinition, SettingEntry},
            repository::{SettingRepository, SettingRepositoryError},
        },
    };

    struct TestSetting;

    impl SettingDefinition for TestSetting {
        type Value = String;

        const KEY: &'static str = "test.setting";

        fn default_value() -> Self::Value {
            "default-value".to_owned()
        }
    }

    #[derive(Clone, Default)]
    struct MockSettingRepo {
        value: Arc<RwLock<Option<Value>>>,
        upsert_calls: Arc<AtomicUsize>,
    }

    impl MockSettingRepo {
        fn empty() -> Self {
            Self::default()
        }

        fn with_initial(value: &str) -> Self {
            Self {
                value: Arc::new(RwLock::new(Some(Value::String(value.to_owned())))),
                upsert_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn overwrite(&self, value: &str) {
            *self.value.write().unwrap() = Some(Value::String(value.to_owned()));
        }

        fn stored_value(&self) -> String {
            self.value
                .read()
                .unwrap()
                .clone()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap()
        }

        fn upsert_calls(&self) -> usize {
            self.upsert_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl SettingRepository for MockSettingRepo {
        async fn get<S>(&self) -> Result<Option<SettingEntry<S::Value>>, SettingRepositoryError>
        where
            S: SettingDefinition,
        {
            let Some(value) = self.value.read().unwrap().clone() else {
                return Ok(None);
            };

            let parsed =
                serde_json::from_value(value).map_err(SettingRepositoryError::Deserialize)?;

            Ok(Some(SettingEntry {
                oid: Uuid::new_v4().into(),
                key: S::KEY.to_owned(),
                value: parsed,
                created_at: Utc::now(),
                updated_at: None,
            }))
        }

        async fn upsert<S>(
            &self,
            value: &S::Value,
        ) -> Result<SettingEntry<S::Value>, SettingRepositoryError>
        where
            S: SettingDefinition,
        {
            self.upsert_calls.fetch_add(1, Ordering::SeqCst);
            let serialized =
                serde_json::to_value(value).map_err(SettingRepositoryError::Serialize)?;
            *self.value.write().unwrap() = Some(serialized);

            Ok(SettingEntry {
                oid: Uuid::new_v4().into(),
                key: S::KEY.to_owned(),
                value: value.clone(),
                created_at: Utc::now(),
                updated_at: None,
            })
        }
    }

    struct CountingRefreshableSetting {
        refresh_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RefreshableSetting for CountingRefreshableSetting {
        fn key(&self) -> &'static str {
            "counting.setting"
        }

        async fn refresh_value(&self) -> Result<(), AppError> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn new_uses_existing_repo_value_without_upsert() {
        let repo = MockSettingRepo::with_initial("repo-value");
        let setting = CachedSetting::<TestSetting, _>::new(repo.clone())
            .await
            .unwrap();

        assert_eq!(setting.current_value().as_ref(), "repo-value");
        assert_eq!(repo.upsert_calls(), 0);
    }

    #[tokio::test]
    async fn new_creates_default_value_when_repo_is_empty() {
        let repo = MockSettingRepo::empty();
        let setting = CachedSetting::<TestSetting, _>::new(repo.clone())
            .await
            .unwrap();

        assert_eq!(setting.current_value().as_ref(), "default-value");
        assert_eq!(repo.stored_value(), "default-value");
        assert_eq!(repo.upsert_calls(), 1);
    }

    #[tokio::test]
    async fn refresh_reloads_the_cached_value() {
        let repo = MockSettingRepo::with_initial("first-value");
        let setting = CachedSetting::<TestSetting, _>::new(repo.clone())
            .await
            .unwrap();
        repo.overwrite("second-value");

        let entry = setting.refresh().await.unwrap();

        assert_eq!(entry.value, "second-value");
        assert_eq!(setting.current_value().as_ref(), "second-value");
    }

    #[tokio::test]
    async fn set_persists_and_updates_the_cached_value() {
        let repo = MockSettingRepo::with_initial("initial-value");
        let setting = CachedSetting::<TestSetting, _>::new(repo.clone())
            .await
            .unwrap();

        let entry = setting.set("updated-value".to_owned()).await.unwrap();

        assert_eq!(entry.value, "updated-value");
        assert_eq!(repo.stored_value(), "updated-value");
        assert_eq!(setting.current_value().as_ref(), "updated-value");
        assert_eq!(repo.upsert_calls(), 1);
    }

    #[tokio::test]
    async fn settings_refresher_ticks_registered_settings() {
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let mut refresher = SettingsRefresher::new(Duration::from_millis(10));
        let setting = Arc::new(CountingRefreshableSetting {
            refresh_calls: refresh_calls.clone(),
        });
        refresher.register(setting);

        let handle = refresher.spawn();
        tokio::time::sleep(Duration::from_millis(35)).await;
        handle.abort();
        let _ = handle.await;

        assert!(refresh_calls.load(Ordering::SeqCst) >= 1);
    }
}
