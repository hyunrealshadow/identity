use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use identity_domain::openid_connect::{LoginRotationPolicy, LoginRuntimeRepository};

use crate::error::{AppError, codes::common::CommonErrorCode};

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
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct LoginRuntimeService {
    repository: Arc<dyn LoginRuntimeRepository>,
    policy: LoginRotationPolicy,
    refresh_after_secs: u64,
}

impl LoginRuntimeService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn LoginRuntimeRepository>,
        policy: LoginRotationPolicy,
        refresh_after_secs: u64,
    ) -> Self {
        Self {
            repository,
            policy,
            refresh_after_secs,
        }
    }

    pub async fn runtime_config(&self) -> Result<Option<RuntimeConfigurationResponse>, AppError> {
        let Some(config) = self
            .repository
            .login_runtime_config(Utc::now())
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?
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
            refresh_after: self.refresh_after_secs,
        }))
    }

    pub async fn maintain(&self) -> Result<u64, AppError> {
        self.repository
            .rotate_if_due(Utc::now(), &self.policy)
            .await
            .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))
    }
}
