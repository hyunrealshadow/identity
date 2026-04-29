use async_trait::async_trait;
use thiserror::Error;

use crate::setting::{SettingDefinition, SettingEntry};

#[derive(Debug, Error)]
pub enum SettingRepositoryError {
    #[error("failed to query setting")]
    QueryFailed(#[source] sea_orm::DbErr),

    #[error("failed to serialize setting value")]
    Serialize(#[source] serde_json::Error),

    #[error("failed to deserialize setting value")]
    Deserialize(#[source] serde_json::Error),

    #[error("invalid setting value: {0}")]
    Validation(String),

    #[error("failed to update setting")]
    UpdateFailed(#[source] sea_orm::DbErr),

    #[error("failed to create setting")]
    CreateFailed(#[source] sea_orm::DbErr),
}

#[async_trait]
pub trait SettingRepository: Send + Sync {
    async fn get<S>(&self) -> Result<Option<SettingEntry<S::Value>>, SettingRepositoryError>
    where
        S: SettingDefinition;

    async fn upsert<S>(
        &self,
        value: &S::Value,
    ) -> Result<SettingEntry<S::Value>, SettingRepositoryError>
    where
        S: SettingDefinition;
}
