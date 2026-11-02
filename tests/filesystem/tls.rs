use crate::temp_dir::TempDir;
use std::{fs, path::Path};

use identity_infrastructure::config::{TlsConfig, TlsTermination};
use identity_infrastructure::crypto::tls::{TlsMode, prepare_tls_material};

const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n";
const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n";

#[test]
fn prepare_uses_existing_pair_without_overwrite() {
    let dir = unique_test_dir("existing-pair");
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    fs::write(&cert_path, CERT_PEM).unwrap();
    fs::write(&key_path, KEY_PEM).unwrap();

    let material = prepare_tls_material(&config(&cert_path, &key_path, true)).unwrap();

    assert_eq!(material.mode, TlsMode::Configured);
    assert_eq!(fs::read_to_string(&cert_path).unwrap(), CERT_PEM);
    assert_eq!(fs::read_to_string(&key_path).unwrap(), KEY_PEM);
    assert_eq!(material.cert_pem, CERT_PEM);
    assert_eq!(material.key_pem, KEY_PEM);
}

#[test]
fn prepare_generates_pair_when_both_files_missing() {
    let dir = unique_test_dir("generate-pair");
    let cert_path = dir.join("nested").join("server.crt");
    let key_path = dir.join("nested").join("server.key");

    let material = prepare_tls_material(&config(&cert_path, &key_path, true)).unwrap();

    assert_eq!(material.mode, TlsMode::Generated);
    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(material.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(material.key_pem.contains("BEGIN PRIVATE KEY"));
    assert_eq!(fs::read_to_string(&cert_path).unwrap(), material.cert_pem);
    assert_eq!(fs::read_to_string(&key_path).unwrap(), material.key_pem);
}

#[test]
fn prepare_fails_for_partial_pair() {
    let dir = unique_test_dir("partial-pair");
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    fs::write(&cert_path, CERT_PEM).unwrap();

    let error = prepare_tls_material(&config(&cert_path, &key_path, true)).unwrap_err();

    assert!(error.to_string().contains("both exist or both be absent"));
}

#[test]
fn prepare_fails_when_generation_disabled_and_files_missing() {
    let dir = unique_test_dir("missing-without-generate");
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");

    let error = prepare_tls_material(&config(&cert_path, &key_path, false)).unwrap_err();

    assert!(error.to_string().contains("auto-generate is disabled"));
}

fn config(cert_path: &Path, key_path: &Path, auto_generate: bool) -> TlsConfig {
    TlsConfig {
        termination: TlsTermination::Direct,
        auto_generate,
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        domain: Some("localhost".to_owned()),
        trusted_proxies: Vec::new(),
        direct_http_clients: Vec::new(),
    }
}

fn unique_test_dir(label: &str) -> TempDir {
    TempDir::new(label)
}
