extern crate identity_application as application;
extern crate identity_domain as domain;
extern crate self as infrastructure;

pub mod auth;
pub mod config;
pub mod context;
pub mod crypto;
pub mod database;
pub mod graphql;
pub mod i18n;
pub mod jobs;
pub mod lifecycle;
pub mod observability;
pub mod openid_connect;
pub mod resources;
pub mod services;
pub mod settings;
pub mod state;
pub mod web;

pub use context::AppContext;
pub use lifecycle::AppLifecycle;
pub use resources::AppResources;
pub use state::AppState;

#[cfg(any(test, feature = "test-support"))]
mod test_support;
#[cfg(any(test, feature = "test-support"))]
pub use test_support::{
    test_app_state_with_cors_origin, test_app_state_with_environment,
    test_app_state_with_mock_settings,
};
