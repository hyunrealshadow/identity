use async_trait::async_trait;

use crate::application::error::AppError;

#[async_trait]
pub trait RefreshableSetting: Send + Sync {
    fn key(&self) -> &'static str;

    async fn refresh_value(&self) -> Result<(), AppError>;
}
