use std::env;

use serde_yml::from_str;
use serial_test::serial;

use super::{AppConfig, AppEnvironment, StaticTokenConfig, render_config_template};

fn set_env(key: &str, value: &str) {
    unsafe { env::set_var(key, value) };
}

fn remove_env(key: &str) {
    unsafe { env::remove_var(key) };
}

#[test]
#[serial]
#[cfg(feature = "oidc-conformance")]
fn detect_conformance_environment() {
    set_env("APP_ENV", "conformance");

    let environment = AppEnvironment::detect();

    remove_env("APP_ENV");

    assert!(matches!(environment, AppEnvironment::Conformance));
    assert!(environment.is_conformance());
    assert!(!environment.is_production());
    assert_eq!(environment.as_str(), "conformance");
}

#[test]
#[serial]
fn detect_prefers_app_env_over_rust_env() {
    set_env("APP_ENV", "production");
    set_env("RUST_ENV", "test");

    let environment = AppEnvironment::detect();

    remove_env("APP_ENV");
    remove_env("RUST_ENV");

    assert!(matches!(environment, AppEnvironment::Production));
}

#[test]
#[serial]
fn detect_uses_rust_env_and_normalizes_custom_values() {
    remove_env("APP_ENV");
    set_env("RUST_ENV", "Staging");

    let environment = AppEnvironment::detect();

    remove_env("RUST_ENV");

    assert!(matches!(environment, AppEnvironment::Custom(value) if value == "staging"));
}

#[test]
#[serial]
fn render_template_uses_default_when_env_is_missing() {
    remove_env("TEST_RENDER_ENV");

    let rendered = render_config_template(
        r#"value: {{ get_env(name="TEST_RENDER_ENV", default="fallback") }}"#,
    )
    .unwrap();

    assert_eq!(rendered, "value: fallback");
    let rendered =
        render_config_template(r#"port: {{ get_env(name="TEST_RENDER_ENV", default=5150) }}"#)
            .unwrap();
    assert_eq!(rendered, "port: 5150");
}

#[test]
#[serial]
fn render_template_errors_when_required_env_is_missing() {
    remove_env("TEST_RENDER_ENV");

    let result = render_config_template(r#"value: {{ get_env(name="TEST_RENDER_ENV") }}"#);

    assert!(result.is_err());
}

#[test]
#[serial]
fn render_template_reads_inline_workload_token() {
    const TOKEN: &str = "local-token-with-at-least-32-characters";
    set_env("TEST_WORKLOAD_TOKEN", TOKEN);

    let rendered =
        render_config_template(r#"token: {{ get_env(name="TEST_WORKLOAD_TOKEN") }}"#).unwrap();
    let config = from_str::<StaticTokenConfig>(&rendered).unwrap();

    remove_env("TEST_WORKLOAD_TOKEN");

    assert_eq!(config.token.as_deref(), Some(TOKEN));
    assert!(config.has_exactly_one_source());
    assert!(!format!("{config:?}").contains(TOKEN));
}

#[test]
fn legacy_fixed_registration_token_config_is_rejected() {
    let result = from_str::<AppConfig>(
        r#"
openid_connect:
  dynamic_registration:
    initial_access_token: long-lived-secret
"#,
    );

    assert!(result.is_err());
}

#[test]
#[cfg(feature = "oidc-conformance")]
fn conformance_registration_token_config_is_explicit() {
    let config = from_str::<AppConfig>(
        r#"
openid_connect:
  dynamic_registration:
    conformance_initial_access_token: " test-secret "
"#,
    )
    .unwrap();

    assert_eq!(
        config
            .openid_connect
            .dynamic_registration
            .required_conformance_initial_access_token(),
        Some("test-secret")
    );
}

#[test]
#[cfg(not(feature = "oidc-conformance"))]
fn conformance_registration_token_config_requires_feature() {
    let result = from_str::<AppConfig>(
        r#"
openid_connect:
  dynamic_registration:
    conformance_initial_access_token: test-secret
"#,
    );

    assert!(result.is_err());
}

#[test]
fn tls_domain_prefers_explicit_value() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://example.com
  tls:
    domain: identity.example.com
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    let config = config.normalized();

    assert_eq!(
        config.server.tls.domain.as_deref(),
        Some("identity.example.com")
    );
}

#[test]
fn tls_domain_falls_back_to_server_host() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com:8443/base
  tls:
    domain: null
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    let config = config.normalized();

    assert_eq!(
        config.server.tls.domain.as_deref(),
        Some("identity.example.com")
    );
}

#[test]
fn graphql_cors_always_allows_the_configured_public_origin() {
    let config = from_str::<AppConfig>(
        r#"
server:
  host: https://identity.example.com:8443/base
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap()
    .normalized();

    assert!(
        config
            .graphql
            .allowed_origins
            .contains(&"https://identity.example.com:8443".to_string())
    );
}

#[test]
fn tls_domain_falls_back_to_localhost_when_host_is_missing() {
    let config: AppConfig = from_str(
        r#"
server:
  tls:
    domain: null
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    let config = config.normalized();

    assert_eq!(config.server.tls.domain.as_deref(), Some("localhost"));
}

#[test]
fn https_contract_rejects_plain_http_host() {
    let config: AppConfig = from_str(
        r#"
server:
  host: http://identity.example.com
  tls:
    termination: upstream
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    let error = config.validate_https_contract().unwrap_err();

    assert!(error.to_string().contains("must use https"));
}

#[test]
fn https_contract_accepts_upstream_tls_termination() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com
  tls:
    termination: upstream
    trusted_proxies:
      - 10.0.0.0/8
internal:
  workloads:
    login:
      static_tokens:
        - file: config/secrets/login-workload-token
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    assert!(config.validate_https_contract().is_ok());
}

#[test]
fn https_contract_accepts_an_explicit_direct_http_client() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com
  tls:
    termination: upstream
    direct_http_clients:
      - 10.42.1.7/32
internal:
  workloads:
    login:
      static_tokens:
        - file: config/secrets/login-workload-token
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    assert!(config.validate_https_contract().is_ok());
}

#[test]
fn internal_login_workload_requires_an_authentication_method() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com
internal:
  server:
    binding: 127.0.0.1
    port: 5151
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    let error = config.validate_https_contract().unwrap_err();

    assert!(error.to_string().contains("workloads.login"));
}

#[test]
fn kubernetes_service_account_authentication_is_accepted() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com
internal:
  workloads:
    login:
      kubernetes_service_account:
        enabled: true
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    assert!(config.validate_https_contract().is_ok());
    let kubernetes = &config.internal.workloads.login.kubernetes_service_account;
    assert!(kubernetes.enabled);
    assert_eq!(kubernetes.audience, "identity-internal");
    assert_eq!(kubernetes.service_account, "identity-login");
    assert_eq!(kubernetes.namespace, "default");
    assert!(kubernetes.ca_file.is_none());
    assert!(kubernetes.token_file.is_none());
}

#[test]
fn kubernetes_service_account_identity_must_be_fully_scoped() {
    let mut config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com
internal:
  workloads:
    login:
      kubernetes_service_account:
        enabled: true
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();
    config
        .internal
        .workloads
        .login
        .kubernetes_service_account
        .namespace = " ".to_owned();

    let error = config.validate_https_contract().unwrap_err();

    assert!(error.to_string().contains("namespace"));
}

#[test]
fn https_contract_rejects_upstream_tls_without_an_allowed_source() {
    let config: AppConfig = from_str(
        r#"
server:
  host: https://identity.example.com
  tls:
    termination: upstream
database:
  uri: postgres://localhost/identity
"#,
    )
    .unwrap();

    let error = config.validate_https_contract().unwrap_err();

    assert!(error.to_string().contains("trusted_proxies"));
}
