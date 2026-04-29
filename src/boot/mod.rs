mod builder;
mod install_guard;
pub mod server;

use std::error::Error;

pub use self::builder::AppBuilder;
pub use identity_infrastructure::{AppContext, AppLifecycle, AppResources, AppState};

pub type AppResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

#[cfg(test)]
pub async fn test_app_state_with_mock_settings() -> AppState {
    identity_infrastructure::test_app_state_with_mock_settings().await
}
