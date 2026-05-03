use std::{fs, io, path::Path};

use crate::config::TlsConfig;
use identity_domain::key::{generator::KeyMaterialError, model::AsymmetricKeyAlgorithm};
use thiserror::Error;

use openssl::{pkey::PKey, rsa::Rsa};

use super::certificate::generate_self_signed_certificate;

fn internal<E>(error: E) -> KeyMaterialError
where
    E: std::error::Error + Send + Sync + 'static,
{
    KeyMaterialError::Internal(Box::new(error))
}

/// Generate a self-signed TLS certificate and private key for the given domain.
///
/// Returns `(cert_pem, key_pem)`.
pub fn generate_self_signed_tls_cert(domain: &str) -> Result<(String, String), KeyMaterialError> {
    let rsa = Rsa::generate(2048).map_err(internal)?;
    let pkey = PKey::from_rsa(rsa).map_err(internal)?;
    let key_pem =
        String::from_utf8(pkey.private_key_to_pem_pkcs8().map_err(internal)?).map_err(internal)?;

    let cert_pem = generate_self_signed_certificate(
        &key_pem,
        domain,
        &AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
    )?;

    Ok((cert_pem, key_pem))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Configured,
    Generated,
}

#[derive(Debug, Clone)]
pub struct PreparedTlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub mode: TlsMode,
}

#[derive(Debug, Error)]
pub enum TlsPrepareError {
    #[error("TLS certificate and private key must both exist or both be absent")]
    PartialPair,

    #[error(
        "TLS certificate files are missing at '{cert_path}' and '{key_path}', and auto-generate is disabled"
    )]
    MissingPair { cert_path: String, key_path: String },

    #[error("failed to create TLS parent directory '{path}': {source}")]
    CreateDirectory {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to read TLS file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to write TLS file '{path}': {source}")]
    WriteFile {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to generate self-signed TLS certificate: {0}")]
    Generate(#[from] KeyMaterialError),
}

pub fn prepare_tls_material(config: &TlsConfig) -> Result<PreparedTlsMaterial, TlsPrepareError> {
    let cert_path = Path::new(&config.cert_path);
    let key_path = Path::new(&config.key_path);
    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();

    match (cert_exists, key_exists) {
        (true, true) => Ok(PreparedTlsMaterial {
            cert_pem: read_file(cert_path)?,
            key_pem: read_file(key_path)?,
            mode: TlsMode::Configured,
        }),
        (false, false) if config.auto_generate => {
            let domain = config
                .domain
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("localhost");
            let (cert_pem, key_pem) = generate_self_signed_tls_cert(domain)?;

            ensure_parent_directory(cert_path)?;
            ensure_parent_directory(key_path)?;
            write_file(cert_path, &cert_pem)?;
            write_file(key_path, &key_pem)?;

            Ok(PreparedTlsMaterial {
                cert_pem,
                key_pem,
                mode: TlsMode::Generated,
            })
        }
        (false, false) => Err(TlsPrepareError::MissingPair {
            cert_path: config.cert_path.clone(),
            key_path: config.key_path.clone(),
        }),
        _ => Err(TlsPrepareError::PartialPair),
    }
}

fn ensure_parent_directory(path: &Path) -> Result<(), TlsPrepareError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.exists() {
        return Ok(());
    }

    fs::create_dir_all(parent).map_err(|source| TlsPrepareError::CreateDirectory {
        path: parent.display().to_string(),
        source,
    })
}

fn read_file(path: &Path) -> Result<String, TlsPrepareError> {
    fs::read_to_string(path).map_err(|source| TlsPrepareError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn write_file(path: &Path, contents: &str) -> Result<(), TlsPrepareError> {
    fs::write(path, contents).map_err(|source| TlsPrepareError::WriteFile {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::config::TlsConfig;

    use super::{TlsMode, prepare_tls_material};

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
            enable: true,
            auto_generate,
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            domain: Some("localhost".to_owned()),
        }
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("identity-tls-{label}-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
