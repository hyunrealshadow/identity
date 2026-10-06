use std::sync::Arc;

use chrono::{DateTime, Utc};
use identity_domain::openid_connect::{LoginRotationPolicy, LoginRuntimeRepository};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::AppError,
    setting::{LoginClientIdSetting, SettingsSource},
};

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeConfigurationResponse {
    pub version: i64,
    pub oauth_client: OAuthClientRuntimeConfiguration,
    pub refresh_after: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OAuthClientRuntimeConfiguration {
    pub client_id: Uuid,
    pub client_secret: String,
    pub generation: i64,
    pub expires_at: DateTime<Utc>,
}

pub struct LoginRuntimeService {
    repository: Arc<dyn LoginRuntimeRepository>,
    settings: Arc<dyn SettingsSource>,
    policy: LoginRotationPolicy,
}

impl LoginRuntimeService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn LoginRuntimeRepository>,
        settings: Arc<dyn SettingsSource>,
    ) -> Self {
        Self {
            repository,
            settings,
            policy: LoginRotationPolicy::default(),
        }
    }

    pub async fn runtime_config(&self) -> Result<Option<RuntimeConfigurationResponse>, AppError> {
        let Some(client_oid) = self.settings.snapshot().get::<LoginClientIdSetting>() else {
            return Ok(None);
        };
        let Some(config) = self
            .repository
            .login_runtime_config(client_oid, Utc::now())
            .await
            .map_err(AppError::internal)?
        else {
            return Ok(None);
        };
        Ok(Some(RuntimeConfigurationResponse {
            version: 1,
            oauth_client: OAuthClientRuntimeConfiguration {
                client_id: config.client_oid,
                client_secret: config.client_secret,
                generation: config.generation,
                expires_at: config.secret_expires_at,
            },
            refresh_after: 60,
        }))
    }

    pub async fn maintain(&self) -> Result<u64, AppError> {
        self.repository
            .rotate_builtin_if_due(Utc::now(), &self.policy)
            .await
            .map_err(AppError::internal)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Duration, Utc};
    use identity_domain::openid_connect::{
        LoginRotationPolicy, LoginRuntimeConfig, LoginRuntimeRepository,
        LoginRuntimeRepositoryError,
    };
    use uuid::Uuid;

    use super::LoginRuntimeService;
    use crate::setting::{LoginClientIdSetting, SettingsSnapshot};

    #[derive(Default)]
    struct RecordingRepository {
        config_ids: Mutex<Vec<Uuid>>,
        rotation_count: Mutex<u64>,
    }

    #[async_trait::async_trait]
    impl LoginRuntimeRepository for RecordingRepository {
        async fn login_runtime_config(
            &self,
            client_oid: Uuid,
            now: DateTime<Utc>,
        ) -> Result<Option<LoginRuntimeConfig>, LoginRuntimeRepositoryError> {
            self.config_ids.lock().unwrap().push(client_oid);
            Ok(Some(LoginRuntimeConfig {
                client_oid,
                client_secret: "login-secret".to_owned(),
                generation: 1,
                secret_expires_at: now + Duration::days(1),
            }))
        }

        async fn rotate_builtin_if_due(
            &self,
            _now: DateTime<Utc>,
            _policy: &LoginRotationPolicy,
        ) -> Result<u64, LoginRuntimeRepositoryError> {
            *self.rotation_count.lock().unwrap() += 1;
            Ok(1)
        }
    }

    fn service(
        repository: Arc<RecordingRepository>,
        settings: SettingsSnapshot,
    ) -> LoginRuntimeService {
        LoginRuntimeService::new(repository, Arc::new(settings))
    }

    #[tokio::test]
    async fn runtime_config_and_rotation_use_the_configured_login_client() {
        let repository = Arc::new(RecordingRepository::default());
        let client_oid = Uuid::new_v4();
        let settings = SettingsSnapshot::default().with::<LoginClientIdSetting>(Some(client_oid));
        let service = service(Arc::clone(&repository), settings);

        let config = service.runtime_config().await.unwrap().unwrap();
        assert_eq!(config.oauth_client.client_id, client_oid);
        assert_eq!(service.maintain().await.unwrap(), 1);
        assert_eq!(*repository.config_ids.lock().unwrap(), vec![client_oid]);
        assert_eq!(*repository.rotation_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn missing_login_client_does_not_block_builtin_rotation() {
        let repository = Arc::new(RecordingRepository::default());
        let service = service(Arc::clone(&repository), SettingsSnapshot::default());

        assert!(service.runtime_config().await.unwrap().is_none());
        assert_eq!(service.maintain().await.unwrap(), 1);
        assert!(repository.config_ids.lock().unwrap().is_empty());
        assert_eq!(*repository.rotation_count.lock().unwrap(), 1);
    }
}
