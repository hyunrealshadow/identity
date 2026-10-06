use std::error::Error;

#[cfg(test)]
use identity_infrastructure::test_app_state_with_mock_settings as infrastructure_test_app_state_with_mock_settings;

mod builder;
mod install_guard;
pub mod server;

pub use self::builder::AppBuilder;
pub use identity_infrastructure::{AppContext, AppLifecycle, AppResources, AppState};

pub type AppResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

#[cfg(test)]
pub async fn test_app_state_with_mock_settings() -> AppState {
    infrastructure_test_app_state_with_mock_settings().await
}
