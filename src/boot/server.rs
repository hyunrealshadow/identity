use std::sync::Arc;

use axum::Router;

use crate::infrastructure::{config::AppConfig, health};

use super::AppResult;
use super::lifecycle::{AppLifecycle, wait_for_shutdown};
use super::state::AppState;

/// Start the main HTTP server (and optionally a separate health-check server)
/// with graceful shutdown support.
pub async fn start_servers(state: &AppState, config: &AppConfig, app: Router) -> AppResult<()> {
    let shared_health = health::shares_listener(&config.health, &config.server);

    let main_address = format!("{}:{}", config.server.binding, config.server.port);
    let main_listener = tokio::net::TcpListener::bind(&main_address).await?;

    let environment = state.context().environment().as_str();
    tracing::info!(environment, address = main_address.as_str(), "listening");

    let needs_separate_health = config.health.enable && !shared_health;

    if needs_separate_health {
        let health_address = health::bind_address(&config.health, &config.server);
        let health_listener = tokio::net::TcpListener::bind(&health_address).await?;
        let health_app = health::router(&config.health).with_state(state.clone());

        tracing::info!(
            environment,
            address = health_address.as_str(),
            route = config.health.route.as_str(),
            "health listening"
        );

        let shutdown = Arc::new(state.lifecycle().clone());
        let health_shutdown = Arc::clone(&shutdown);

        tokio::try_join!(
            serve_with_shutdown(main_listener, app, shutdown),
            serve_with_shutdown(health_listener, health_app, health_shutdown),
        )?;
    } else {
        let shutdown = Arc::new(state.lifecycle().clone());
        serve_with_shutdown(main_listener, app, shutdown).await?;
    }

    Ok(())
}

async fn serve_with_shutdown(
    listener: tokio::net::TcpListener,
    app: Router,
    lifecycle: Arc<AppLifecycle>,
) -> Result<(), std::io::Error> {
    axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown(lifecycle))
        .await
}
