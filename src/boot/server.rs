use std::sync::Arc;

use salvo::{
    Listener, Router, Server,
    conn::{
        Acceptor, TcpListener,
        rustls::{Keycert, RustlsConfig},
    },
};

use identity_infrastructure::{
    config::{AppConfig, TlsTermination},
    crypto::tls::{TlsMode, prepare_tls_material},
    lifecycle::{AppLifecycle, wait_for_shutdown},
    state::AppState,
};
use identity_web::{graphql, health};

use super::AppResult;

/// Start the main HTTP server (and optionally a separate health-check server)
/// with graceful shutdown support.
pub async fn start_servers(
    state: &AppState,
    config: &AppConfig,
    app: Router,
    internal: Router,
) -> AppResult<()> {
    if config.client_credential_rotation.enable {
        spawn_login_runtime_rotation_worker(
            state.clone(),
            config.client_credential_rotation.check_interval_secs,
        );
    }
    let shared_health = health::shares_listener(&config.health, &config.server);
    let shared_graphql = graphql::shares_listener(&config.graphql, &config.server);

    let main_address = format!("{}:{}", config.server.binding, config.server.port);
    let internal_address = format!(
        "{}:{}",
        config.internal.server.binding, config.internal.server.port
    );
    let environment = state.context().environment().as_str();

    let needs_separate_health = config.health.enable && !shared_health;
    let needs_separate_graphql = !shared_graphql;
    let shutdown = Arc::new(state.lifecycle().clone());
    let mut servers = tokio::task::JoinSet::new();

    match listener_mode(config) {
        ListenerMode::UpstreamTls => {
            let main_listener = build_upstream_tls_listener(&main_address).await?;
            servers.spawn(serve_with_shutdown(
                main_listener,
                app,
                Arc::clone(&shutdown),
            ));
            let internal_listener = build_upstream_tls_listener(&internal_address).await?;
            tracing::info!(address = internal_address, "internal API listening");
            servers.spawn(serve_with_shutdown(
                internal_listener,
                internal,
                Arc::clone(&shutdown),
            ));
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
                servers.spawn(serve_with_shutdown(
                    health_listener,
                    health_app,
                    Arc::clone(&shutdown),
                ));
            }
            if needs_separate_graphql {
                let graphql_address = graphql::bind_address(&config.graphql, &config.server);
                let graphql_listener = build_upstream_tls_listener(&graphql_address).await?;
                let graphql_app = graphql::router(state.clone(), &config.graphql).hoop(
                    identity_web::middleware::RequireUpstreamHttps::new(
                        &config.server.tls.trusted_proxies,
                        &config.server.tls.direct_http_clients,
                    ),
                );
                tracing::info!(
                    environment,
                    address = graphql_address.as_str(),
                    route = "/graphql",
                    "graphql listening"
                );
                servers.spawn(serve_with_shutdown(
                    graphql_listener,
                    graphql_app,
                    Arc::clone(&shutdown),
                ));
            }
        }
        ListenerMode::DirectTls => {
            let main_listener = build_https_listener(config, &main_address).await?;
            servers.spawn(serve_with_shutdown(
                main_listener,
                app,
                Arc::clone(&shutdown),
            ));
            let internal_listener = build_https_listener(config, &internal_address).await?;
            tracing::info!(address = internal_address, "internal API listening");
            servers.spawn(serve_with_shutdown(
                internal_listener,
                internal,
                Arc::clone(&shutdown),
            ));
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
                servers.spawn(serve_with_shutdown(
                    health_listener,
                    health_app,
                    Arc::clone(&shutdown),
                ));
            }
            if needs_separate_graphql {
                let graphql_address = graphql::bind_address(&config.graphql, &config.server);
                let graphql_listener = build_https_listener(config, &graphql_address).await?;
                let graphql_app = graphql::router(state.clone(), &config.graphql);
                tracing::info!(
                    environment,
                    address = graphql_address.as_str(),
                    route = "/graphql",
                    "graphql listening"
                );
                servers.spawn(serve_with_shutdown(
                    graphql_listener,
                    graphql_app,
                    Arc::clone(&shutdown),
                ));
            }
        }
    }

    while let Some(result) = servers.join_next().await {
        result??;
        if !state.lifecycle().shutdown_requested() {
            return Err(std::io::Error::other("HTTP listener stopped unexpectedly").into());
        }
    }

    Ok(())
}

fn spawn_login_runtime_rotation_worker(state: AppState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut shutdown = state.lifecycle().subscribe_shutdown();
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = state.services().login_runtime().maintain().await {
                        tracing::error!(error = %error, "login runtime rotation maintenance failed");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });
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
    DirectTls,
    UpstreamTls,
}

fn listener_mode(config: &AppConfig) -> ListenerMode {
    match config.server.tls.termination {
        TlsTermination::Direct => ListenerMode::DirectTls,
        TlsTermination::Upstream => ListenerMode::UpstreamTls,
    }
}

async fn build_upstream_tls_listener(address: &str) -> AppResult<salvo::conn::tcp::TcpAcceptor> {
    tracing::info!(
        address,
        mode = "upstream-tls",
        "tls is terminated by a trusted upstream proxy"
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
        AppConfig, DatabaseConfig, GraphqlConfig, HealthConfig, LoggerConfig, ServerConfig,
        SettingsConfig, TlsTermination,
    };

    use super::{ListenerMode, build_https_listener, listener_mode};

    #[test]
    fn listener_mode_is_upstream_tls_when_configured() {
        let config = app_config(TlsTermination::Upstream);

        assert!(matches!(listener_mode(&config), ListenerMode::UpstreamTls));
    }

    #[test]
    fn listener_mode_is_https_when_tls_enabled() {
        let config = app_config(TlsTermination::Direct);

        assert!(matches!(listener_mode(&config), ListenerMode::DirectTls));
    }

    #[tokio::test]
    async fn build_https_listener_accepts_generated_tls_material() {
        let dir = unique_test_dir("https-listener");
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");

        let mut config = app_config(TlsTermination::Direct);
        config.server.binding = "127.0.0.1".to_owned();
        config.server.tls.auto_generate = true;
        config.server.tls.cert_path = cert_path.to_string_lossy().into_owned();
        config.server.tls.key_path = key_path.to_string_lossy().into_owned();
        config.server.tls.domain = Some("localhost".to_owned());

        let _listener = build_https_listener(&config, "127.0.0.1:0").await.unwrap();

        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    fn app_config(termination: TlsTermination) -> AppConfig {
        let mut config = AppConfig {
            logger: LoggerConfig::default(),
            server: ServerConfig::default(),
            internal: Default::default(),
            client_credential_rotation: Default::default(),
            database: DatabaseConfig::default(),
            health: HealthConfig::default(),
            graphql: GraphqlConfig::default(),
            openid_connect: Default::default(),
            settings: SettingsConfig::default(),
            install: Default::default(),
        };
        config.server.tls.termination = termination;
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
