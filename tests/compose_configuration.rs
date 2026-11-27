//! Load rendered Docker Compose Identity configurations through the production loader.
#[path = "support/temp_dir.rs"]
mod temp_dir;

use std::{env, fs, path::PathBuf};

use identity_infrastructure::config::{AppConfig, AppEnvironment, TlsTermination};
use temp_dir::TempDir;

struct WorkingDirectory(PathBuf);

impl Drop for WorkingDirectory {
    fn drop(&mut self) {
        env::set_current_dir(&self.0).unwrap();
    }
}

fn render_compose_template(raw: &str) -> String {
    raw.replace(
        "{{ get_env(name=\"DATABASE_URL\") }}",
        "postgres://localhost/unused-test-database",
    )
    .replace(
        "{{ get_env(name=\"IDENTITY_OTLP_ENABLE\", default=\"false\") }}",
        "false",
    )
    .replace(
        "{{ get_env(name=\"OTEL_EXPORTER_OTLP_ENDPOINT\", default=\"http://otel-collector:4318\") }}",
        "http://otel-collector:4318",
    )
    .replace(
        "{{ get_env(name=\"IDENTITY_TRUSTED_PROXY\") }}",
        "172.18.0.0/16",
    )
    .replace(
        "{{ get_env(name=\"IDENTITY_DIRECT_HTTP_CLIENT\") }}",
        "172.18.0.0/16",
    )
}

#[test]
fn compose_configurations_load_and_validate() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temporary = TempDir::new("compose-configuration");
    let _restore = WorkingDirectory(env::current_dir().unwrap());
    let configuration = temporary.join("config");
    fs::create_dir(&configuration).unwrap();
    let environment = AppEnvironment::detect();

    for (relative_path, expected_termination) in [
        (
            "deploy/config/identity.compose.yaml",
            TlsTermination::Direct,
        ),
        (
            "deploy/config/identity.compose.upstream.yaml",
            TlsTermination::Upstream,
        ),
    ] {
        let raw = fs::read_to_string(workspace.join(relative_path)).unwrap();
        let yaml = render_compose_template(&raw);
        fs::write(
            configuration.join(format!("{}.yaml", environment.as_str())),
            yaml,
        )
        .unwrap();

        env::set_current_dir(temporary.as_ref()).unwrap();
        let (config, _) = AppConfig::load().unwrap();

        assert!(config.internal.workloads.login.has_any_authentication());
        assert!(config.internal.workloads.console.has_any_authentication());
        assert_eq!(config.server.port, 5150);
        assert_eq!(config.graphql.server.port, Some(5150));
        assert!(config.server.host.is_none());
        assert_eq!(config.server.tls.termination, expected_termination);
        if expected_termination == TlsTermination::Upstream {
            assert!(!config.server.tls.trusted_proxies.is_empty());
            assert!(!config.server.tls.direct_http_clients.is_empty());
        }
    }
}
