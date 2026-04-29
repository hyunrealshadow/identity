use std::sync::Arc;

use salvo::{Listener, Router, Server, conn::TcpListener};

use identity_infrastructure::{
    config::AppConfig,
    lifecycle::{AppLifecycle, wait_for_shutdown},
    state::AppState,
};
use identity_web::health;

use super::AppResult;

/// Start the main HTTP server (and optionally a separate health-check server)
/// with graceful shutdown support.
pub async fn start_servers(state: &AppState, config: &AppConfig, app: Router) -> AppResult<()> {
    let shared_health = health::shares_listener(&config.health, &config.server);

    let main_address = format!("{}:{}", config.server.binding, config.server.port);
    let main_listener = TcpListener::new(main_address.clone()).try_bind().await?;

    let environment = state.context().environment().as_str();
    tracing::info!(environment, address = main_address.as_str(), "listening");

    let needs_separate_health = config.health.enable && !shared_health;

    if needs_separate_health {
        let health_address = health::bind_address(&config.health, &config.server);
        let health_listener = TcpListener::new(health_address.clone()).try_bind().await?;
        let health_app =
            health::router(&config.health).hoop(salvo::affix_state::inject(state.clone()));

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
    acceptor: salvo::conn::tcp::TcpAcceptor,
    app: Router,
    lifecycle: Arc<AppLifecycle>,
) -> Result<(), std::io::Error> {
    let server = Server::new(acceptor);
    let handle = server.handle();

    tokio::spawn(async move {
        wait_for_shutdown(lifecycle).await;
        handle.stop_graceful(None);
    });

    server.serve(app).await;
    Ok(())
}
