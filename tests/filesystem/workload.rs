use crate::temp_dir::TempDir;
use identity_domain::openid_connect::{
    AuthenticatedWorkload, BuiltInWorkload, WorkloadAuthenticator as _,
};
use identity_infrastructure::auth::workload::StaticTokenWorkloadAuthenticator;
use std::{fs, path::PathBuf};
#[tokio::test]
async fn static_token_accepts_configured_tokens() {
    let dir = TempDir::new("identity-wl");
    let current = dir.join("current");
    let previous = dir.join("previous");
    fs::write(&current, "current-workload-token-0123456789abcdef").unwrap();
    fs::write(&previous, "previous-workload-token-0123456789abcdef").unwrap();

    let authenticator = StaticTokenWorkloadAuthenticator::new(
        vec![PathBuf::from(&current), PathBuf::from(&previous)],
        Vec::new(),
        BuiltInWorkload::Login,
    )
    .unwrap();

    assert_eq!(
        authenticator
            .authenticate("current-workload-token-0123456789abcdef")
            .await,
        Some(AuthenticatedWorkload(BuiltInWorkload::Login))
    );
    assert_eq!(
        authenticator
            .authenticate("previous-workload-token-0123456789abcdef")
            .await,
        Some(AuthenticatedWorkload(BuiltInWorkload::Login))
    );
    assert_eq!(
        authenticator.authenticate("wrong-workload-token").await,
        None
    );
}
#[tokio::test]
async fn static_token_normalizes_file_whitespace() {
    let dir = TempDir::new("identity-wl-trim");
    let token_file = dir.join("token");
    fs::write(&token_file, "workload-token-with-32-characters-minimum\r\n").unwrap();

    let authenticator = StaticTokenWorkloadAuthenticator::new(
        vec![token_file.clone()],
        Vec::new(),
        BuiltInWorkload::Login,
    )
    .unwrap();

    assert_eq!(
        authenticator
            .authenticate("workload-token-with-32-characters-minimum")
            .await,
        Some(AuthenticatedWorkload(BuiltInWorkload::Login))
    );
}
#[test]
fn static_token_rejects_short_or_missing_sources() {
    let dir = TempDir::new("identity-wl-short");
    let short = dir.join("short");
    fs::write(&short, "too-short").unwrap();

    let error = StaticTokenWorkloadAuthenticator::new(
        vec![PathBuf::from(&short)],
        Vec::new(),
        BuiltInWorkload::Login,
    )
    .err()
    .expect("short token must be rejected");
    assert!(error.contains("32 characters"));

    let error =
        StaticTokenWorkloadAuthenticator::new(Vec::new(), Vec::new(), BuiltInWorkload::Login)
            .err()
            .expect("missing sources must be rejected");
    assert!(error.contains("at least one token file"));
}
