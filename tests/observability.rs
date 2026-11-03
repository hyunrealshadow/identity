use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    spawn,
    sync::Mutex,
    task, time,
    time::sleep,
};

use identity_application::{
    observability as identity_application_observability, observability::BusinessEvent,
};
use identity_infrastructure::{
    config::{AppConfig, AppEnvironment},
    observability,
};

#[derive(Clone, Debug, Default)]
struct MockCollector {
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockCollector {
    async fn start() -> (Self, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let collector = Self::default();
        let requests = Arc::clone(&collector.requests);
        spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let requests = Arc::clone(&requests);
                spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0_u8; 8192];
                    loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => read,
                        };
                        buffer.extend_from_slice(&chunk[..read]);
                        let Some(headers_end) =
                            buffer.windows(4).position(|window| window == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&buffer[..headers_end]).to_string();
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if buffer.len() >= headers_end + 4 + content_length {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&buffer).to_string();
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_owned();
                    let body = request
                        .split("\r\n\r\n")
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned();
                    requests.lock().await.push((path, body));
                    let response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (collector, format!("http://{address}"))
    }
}

#[tokio::test]
async fn exports_spans_and_logs_to_the_configured_collector() {
    let (collector, endpoint) = MockCollector::start().await;
    let mut config = AppConfig {
        logger: Default::default(),
        server: Default::default(),
        internal: Default::default(),
        database: Default::default(),
        health: Default::default(),
        graphql: Default::default(),
        console: Default::default(),
        observability: Default::default(),
        openid_connect: Default::default(),
        settings: Default::default(),
        install: Default::default(),
    };
    config.logger.enable = false;
    config.observability.console = Some(false);
    config.observability.otlp.enable = true;
    config.observability.otlp.endpoint = endpoint;
    config.observability.diagnostics.schedule_delay_ms = 10;
    // Initialization inside the async runtime and real export share the production entry point.
    observability::init(&config, &AppEnvironment::Development).unwrap();
    assert!(observability::is_initialized());
    let span = tracing::info_span!(target: "identity", "export.test.span");
    {
        let _entered = span.enter();
    }
    drop(span);
    identity_application_observability::event_sink()
        .emit(BusinessEvent::business("export.test.event"));
    time::timeout(Duration::from_secs(5), async {
        loop {
            let requests = collector.requests.lock().await;
            let ready = ["/v1/traces", "/v1/logs"]
                .iter()
                .all(|path| requests.iter().any(|(actual, _)| actual == path));
            drop(requests);
            if ready {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("configured providers must export both signals");
    task::spawn_blocking(|| observability::shutdown(Duration::from_secs(2)))
        .await
        .unwrap();
    let requests = collector.requests.lock().await.clone();
    let paths: Vec<&str> = requests.iter().map(|(path, _)| path.as_str()).collect();
    assert!(paths.contains(&"/v1/traces"), "requests: {paths:?}");
    assert!(paths.contains(&"/v1/logs"), "requests: {paths:?}");
    let trace_body = &requests
        .iter()
        .find(|(path, _)| path == "/v1/traces")
        .unwrap()
        .1;
    assert!(!trace_body.is_empty());
    let log_body = &requests
        .iter()
        .find(|(path, _)| path == "/v1/logs")
        .unwrap()
        .1;
    assert!(!log_body.is_empty());
}
