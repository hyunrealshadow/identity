//! Load actual rendered deployment configuration through the production loader.
#[path = "support/temp_dir.rs"]
mod temp_dir;

use std::{env, fs, path::PathBuf, process::Command};

use identity_infrastructure::config::{AppConfig, AppEnvironment, TlsTermination};

struct WorkingDirectory(PathBuf);

impl Drop for WorkingDirectory {
    fn drop(&mut self) {
        env::set_current_dir(&self.0).unwrap();
    }
}

#[test]
#[ignore = "requires Helm installed; no database or cluster access"]
fn rendered_helm_configuration_loads_without_a_public_host() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temporary = temp_dir::TempDir::new("helm-configuration");
    let _restore = WorkingDirectory(env::current_dir().unwrap());
    let configuration = temporary.join("config");
    fs::create_dir(&configuration).unwrap();
    let environment = AppEnvironment::detect();
    for direct_tls in [true, false] {
        let rendered = Command::new("helm")
            .args([
                "template",
                "verify",
                "deploy/helm/identity",
                "--show-only",
                "templates/configmap.yaml",
                "--set",
                &format!("identity.tls.enabled={direct_tls}"),
                "--set",
                "identity.tls.trustedProxies[0]=10.42.0.0/16",
            ])
            .current_dir(&workspace)
            .output()
            .unwrap();
        assert!(
            rendered.status.success(),
            "{}",
            String::from_utf8_lossy(&rendered.stderr)
        );
        let rendered = String::from_utf8(rendered.stdout).unwrap();
        let yaml = rendered
            .split_once("  production.yaml: |\n")
            .unwrap()
            .1
            .lines()
            .map(|line| line.strip_prefix("    ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(
                "{{ get_env(name=\"DATABASE_URL\") }}",
                "postgres://localhost/unused-test-database",
            );
        fs::write(
            configuration.join(format!("{}.yaml", environment.as_str())),
            yaml,
        )
        .unwrap();
        env::set_current_dir(temporary.as_ref()).unwrap();
        let (mut config, _) = AppConfig::load().unwrap();
        assert!(config.server.host.is_none());
        assert!(config.graphql.allowed_origins.is_empty());
        if !direct_tls {
            assert_eq!(config.server.tls.termination, TlsTermination::Upstream);
            let trusted_proxies = config.server.tls.trusted_proxies.clone();
            config.server.tls.trusted_proxies.clear();
            assert!(
                config
                    .validate_https_contract()
                    .unwrap_err()
                    .to_string()
                    .contains("trusted_proxies")
            );
            config.server.tls.trusted_proxies = trusted_proxies;
        }
        config
            .internal
            .workloads
            .login
            .kubernetes_service_account
            .enabled = false;
        assert!(
            config
                .validate_https_contract()
                .unwrap_err()
                .to_string()
                .contains("workloads.login"),
            "missing public host must not bypass workload admission"
        );
    }
}
