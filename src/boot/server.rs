use std::sync::Arc;

use salvo::{
    Listener, Router, Server,
    conn::{
        Acceptor, TcpListener,
        rustls::{Keycert, RustlsConfig},
    },
};

use identity_infrastructure::{
    config::AppConfig,
    crypto::tls::{TlsMode, prepare_tls_material},
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
    let environment = state.context().environment().as_str();

    let needs_separate_health = config.health.enable && !shared_health;

    match listener_mode(config) {
        ListenerMode::Http => {
            let main_listener = build_http_listener(&main_address).await?;

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
        }
        ListenerMode::Https => {
            let main_listener = build_https_listener(config, &main_address).await?;

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
        }
    }

    Ok(())
}

async fn serve_with_shutdown<A>(
    acceptor: A,
    app: Router,
    lifecycle: Arc<AppLifecycle>,
) -> Result<(), std::io::Error>
where
    A: Acceptor + Send,
{
    let server = Server::new(acceptor);
    let handle = server.handle();

    tokio::spawn(async move {
        wait_for_shutdown(lifecycle).await;
        handle.stop_graceful(None);
    });

    server.serve(app).await;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerMode {
    Http,
    Https,
}

fn listener_mode(config: &AppConfig) -> ListenerMode {
    if config.server.tls.enable {
        ListenerMode::Https
    } else {
        ListenerMode::Http
    }
}

async fn build_http_listener(address: &str) -> AppResult<salvo::conn::tcp::TcpAcceptor> {
    tracing::info!(
        address,
        mode = "http",
        "tls disabled; starting plain http listener"
    );
    Ok(TcpListener::new(address.to_owned()).try_bind().await?)
}

async fn build_https_listener(
    config: &AppConfig,
    address: &str,
) -> AppResult<salvo::conn::rustls::RustlsAcceptor<salvo::conn::tcp::TcpAcceptor>> {
    let material = prepare_tls_material(&config.server.tls)?;
    log_tls_startup(address, config, material.mode);
    ensure_rustls_crypto_provider();

    let tls_config = RustlsConfig::new(
        Keycert::new()
            .cert(material.cert_pem.into_bytes())
            .key(material.key_pem.into_bytes()),
    );

    Ok(TcpListener::new(address.to_owned())
        .rustls(tls_config)
        .try_bind()
        .await?)
}

fn ensure_rustls_crypto_provider() {
    use rustls::crypto::{CryptoProvider, aws_lc_rs};

    if CryptoProvider::get_default().is_none() {
        let _ = aws_lc_rs::default_provider().install_default();
    }
}

fn log_tls_startup(address: &str, config: &AppConfig, mode: TlsMode) {
    match mode {
        TlsMode::Configured => tracing::info!(
            address,
            cert_path = config.server.tls.cert_path.as_str(),
            key_path = config.server.tls.key_path.as_str(),
            mode = "https-configured",
            "tls enabled using configured certificate files"
        ),
        TlsMode::Generated => tracing::info!(
            address,
            cert_path = config.server.tls.cert_path.as_str(),
            key_path = config.server.tls.key_path.as_str(),
            mode = "https-generated",
            "tls enabled with auto-generated self-signed certificate"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use identity_infrastructure::config::{
        AppConfig, DatabaseConfig, HealthConfig, LoggerConfig, ServerConfig, SettingsConfig,
    };

    use super::{ListenerMode, build_https_listener, listener_mode};

    #[test]
    fn listener_mode_is_http_when_tls_disabled() {
        let config = app_config(false);

        assert!(matches!(listener_mode(&config), ListenerMode::Http));
    }

    #[test]
    fn listener_mode_is_https_when_tls_enabled() {
        let config = app_config(true);

        assert!(matches!(listener_mode(&config), ListenerMode::Https));
    }

    #[tokio::test]
    async fn build_https_listener_accepts_generated_tls_material() {
        let dir = unique_test_dir("https-listener");
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");

        let mut config = app_config(true);
        config.server.binding = "127.0.0.1".to_owned();
        config.server.tls.auto_generate = true;
        config.server.tls.cert_path = cert_path.to_string_lossy().into_owned();
        config.server.tls.key_path = key_path.to_string_lossy().into_owned();
        config.server.tls.domain = Some("localhost".to_owned());

        let _listener = build_https_listener(&config, "127.0.0.1:0").await.unwrap();

        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    fn app_config(tls_enabled: bool) -> AppConfig {
        let mut config = AppConfig {
            logger: LoggerConfig::default(),
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            health: HealthConfig::default(),
            settings: SettingsConfig::default(),
        };
        config.server.tls.enable = tls_enabled;
        config
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("identity-boot-{label}-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
