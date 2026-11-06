use std::{io::Error, net::UdpSocket, sync::Arc};

use identity_infrastructure::{
    config::{AppConfig, TlsTermination},
    crypto::tls::{TlsMode, prepare_tls_material},
    jobs::spawn_background_workers,
    lifecycle::{AppLifecycle, wait_for_shutdown},
    observability::context::TraceTrustPolicy,
    state::AppState,
};
use identity_web::{
    graphql, health,
    middleware::{RequestIdMiddleware, RequireUpstreamHttps, TraceContextMiddleware},
};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use salvo::{
    Listener, Router, Server,
    affix_state::inject,
    conn::{
        Acceptor, TcpListener,
        rustls::{Keycert, RustlsAcceptor, RustlsConfig},
        tcp::TcpAcceptor,
    },
};
use tokio::{spawn, task::JoinSet};
use tracing::{info, warn};

use super::AppResult;

/// Start the main HTTP server (and optionally a separate health-check server)
/// with graceful shutdown support.
pub async fn start_servers(
    state: &AppState,
    config: &AppConfig,
    app: Router,
    internal: Router,
) -> AppResult<()> {
    spawn_background_workers(state.clone(), config).await?;
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
    let mut servers = JoinSet::new();

    let mode = listener_mode(config);
    spawn_app(&mut servers, config, mode, &main_address, app, &shutdown).await?;
    spawn_app(
        &mut servers,
        config,
        mode,
        &internal_address,
        internal,
        &shutdown,
    )
    .await?;
    info!(address = internal_address, "internal API listening");

    if needs_separate_health {
        let health_address = health::bind_address(&config.health, &config.server);
        let health_app = health::router(&config.health)
            .hoop(inject(state.clone()))
            .hoop(TraceContextMiddleware::new(TraceTrustPolicy::new(
                config.observability.trace_context.clone(),
            )));
        // The health probe stays plain TCP in both modes.
        let health_app = Arc::new(health_app);
        for address in listen_addresses(&health_address) {
            let listener = TcpListener::new(address).try_bind().await?;
            servers.spawn(serve_with_shutdown(
                listener,
                Arc::clone(&health_app),
                Arc::clone(&shutdown),
            ));
        }
        info!(
            environment,
            address = health_address.as_str(),
            route = config.health.route.as_str(),
            "health listening"
        );
    }

    if needs_separate_graphql {
        let graphql_address = graphql::bind_address(&config.graphql, &config.server);
        let trace_context = TraceContextMiddleware::new(TraceTrustPolicy::new(
            config.observability.trace_context.clone(),
        ));
        let graphql_app = match mode {
            ListenerMode::UpstreamTls => graphql::router(state.clone(), &config.graphql)
                .hoop(RequestIdMiddleware::new(TraceTrustPolicy::new(
                    config.observability.trace_context.clone(),
                )))
                .hoop(RequireUpstreamHttps::new(
                    &config.server.tls.trusted_proxies,
                    &config.server.tls.direct_http_clients,
                ))
                .hoop(trace_context),
            ListenerMode::DirectTls => {
                graphql::router(state.clone(), &config.graphql).hoop(trace_context)
            }
        };
        spawn_app(
            &mut servers,
            config,
            mode,
            &graphql_address,
            graphql_app,
            &shutdown,
        )
        .await?;
        info!(
            environment,
            address = graphql_address.as_str(),
            route = "/graphql",
            "graphql listening"
        );
    }

    while let Some(result) = servers.join_next().await {
        result??;
        if !state.lifecycle().shutdown_requested() {
            return Err(Error::other("HTTP listener stopped unexpectedly").into());
        }
    }

    Ok(())
}

async fn serve_with_shutdown<A>(
    acceptor: A,
    app: Arc<Router>,
    lifecycle: Arc<AppLifecycle>,
) -> Result<(), Error>
where
    A: Acceptor + Send,
{
    let server = Server::new(acceptor);
    let handle = server.handle();

    spawn(async move {
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

/// Binds every listen address of one configured address and serves the same
/// router on each of them.
async fn spawn_app(
    servers: &mut JoinSet<Result<(), Error>>,
    config: &AppConfig,
    mode: ListenerMode,
    address: &str,
    app: Router,
    shutdown: &Arc<AppLifecycle>,
) -> AppResult<()> {
    let app = Arc::new(app);
    for address in listen_addresses(address) {
        match mode {
            ListenerMode::UpstreamTls => {
                let listener = build_upstream_tls_listener(&address).await?;
                servers.spawn(serve_with_shutdown(
                    listener,
                    Arc::clone(&app),
                    Arc::clone(shutdown),
                ));
            }
            ListenerMode::DirectTls => {
                let listener = build_https_listener(config, &address).await?;
                servers.spawn(serve_with_shutdown(
                    listener,
                    Arc::clone(&app),
                    Arc::clone(shutdown),
                ));
            }
        }
    }
    Ok(())
}

/// The socket addresses to bind for a configured `host:port`.
///
/// `localhost` resolves to a single address family, which differs between
/// systems: a client that resolves it to the other family would be refused.
/// It therefore binds both loopback addresses. The IPv6 loopback is skipped
/// on hosts without IPv6. Any other host is bound exactly as configured.
fn listen_addresses(address: &str) -> Vec<String> {
    expand_localhost(address, ipv6_loopback_available())
}

fn expand_localhost(address: &str, ipv6: bool) -> Vec<String> {
    let Some((host, port)) = address.rsplit_once(':') else {
        return vec![address.to_owned()];
    };
    if !host.eq_ignore_ascii_case("localhost") {
        return vec![address.to_owned()];
    }
    let mut addresses = vec![format!("127.0.0.1:{port}")];
    if ipv6 {
        addresses.push(format!("[::1]:{port}"));
    } else {
        warn!(
            address,
            "IPv6 loopback is unavailable; listening on 127.0.0.1 only"
        );
    }
    addresses
}

fn ipv6_loopback_available() -> bool {
    UdpSocket::bind("[::1]:0").is_ok()
}

async fn build_upstream_tls_listener(address: &str) -> AppResult<TcpAcceptor> {
    info!(
        address,
        mode = "upstream-tls",
        "tls is terminated by a trusted upstream proxy"
    );
    Ok(TcpListener::new(address.to_owned()).try_bind().await?)
}

async fn build_https_listener(
    config: &AppConfig,
    address: &str,
) -> AppResult<RustlsAcceptor<TcpAcceptor>> {
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
    if CryptoProvider::get_default().is_none() {
        let _ = aws_lc_rs::default_provider().install_default();
    }
}

fn log_tls_startup(address: &str, config: &AppConfig, mode: TlsMode) {
    match mode {
        TlsMode::Configured => info!(
            address,
            cert_path = config.server.tls.cert_path.as_str(),
            key_path = config.server.tls.key_path.as_str(),
            mode = "https-configured",
            "tls enabled using configured certificate files"
        ),
        TlsMode::Generated => info!(
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
    use identity_infrastructure::config::{
        AppConfig, DatabaseConfig, GraphqlConfig, HealthConfig, LoggerConfig, ServerConfig,
        SettingsConfig, TlsTermination,
    };

    use super::{ListenerMode, expand_localhost, listener_mode};

    #[test]
    fn localhost_binds_both_loopback_families() {
        assert_eq!(
            expand_localhost("localhost:5150", true),
            ["127.0.0.1:5150", "[::1]:5150"]
        );
        assert_eq!(
            expand_localhost("LocalHost:5151", true),
            ["127.0.0.1:5151", "[::1]:5151"]
        );
    }

    #[test]
    fn localhost_falls_back_to_ipv4_without_ipv6() {
        assert_eq!(
            expand_localhost("localhost:5150", false),
            ["127.0.0.1:5150"]
        );
    }

    #[test]
    fn other_hosts_bind_as_configured() {
        for address in [
            "0.0.0.0:5150",
            "127.0.0.1:5150",
            "[::1]:5150",
            "[::]:5150",
            "example.test:5150",
        ] {
            assert_eq!(expand_localhost(address, true), [address]);
        }
    }

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

    fn app_config(termination: TlsTermination) -> AppConfig {
        let mut config = AppConfig {
            logger: LoggerConfig::default(),
            server: ServerConfig::default(),
            internal: Default::default(),
            database: DatabaseConfig::default(),
            health: HealthConfig::default(),
            graphql: GraphqlConfig::default(),
            console: Default::default(),
            observability: Default::default(),
            openid_connect: Default::default(),
            settings: SettingsConfig::default(),
            install: Default::default(),
        };
        config.server.tls.termination = termination;
        config
    }
}
