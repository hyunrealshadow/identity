use std::{sync::Arc, time::Duration};

use identity_application::setting::runtime::RefreshableSetting;
use tokio::{
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

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

                let round = tracing::info_span!(
                    "settings.refresh.round",
                    setting_count = self.settings.len(),
                );
                for setting in &self.settings {
                    let _entered = round.enter();
                    if let Err(error) = setting.refresh_value().await {
                        tracing::warn!(
                            key = setting.key(),
                            error = %error,
                            "failed to refresh setting"
                        );
                    }
                }
            }
        })
    }

    pub fn spawn_detached(self) {
        drop(self.spawn());
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;
    use tokio::time::timeout;

    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use identity_application::{error::AppError, setting::runtime::RefreshableSetting};

    use super::SettingsRefresher;

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
    async fn settings_refresher_ticks_registered_settings() {
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let mut refresher = SettingsRefresher::new(Duration::from_millis(10));
        let setting = Arc::new(CountingRefreshableSetting {
            refresh_calls: refresh_calls.clone(),
        });
        refresher.register(setting);

        let handle = refresher.spawn();
        timeout(Duration::from_millis(250), async {
            while refresh_calls.load(Ordering::SeqCst) == 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("settings refresher should tick at least once");
        handle.abort();
        let _ = handle.await;

        assert!(refresh_calls.load(Ordering::SeqCst) >= 1);
    }
}
