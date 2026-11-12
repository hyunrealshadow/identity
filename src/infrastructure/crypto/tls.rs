use std::{error::Error as StdError, fs, io, path::Path};

use identity_domain::key::{generator::KeyMaterialError, model::AsymmetricKeyAlgorithm};
use openssl::{pkey::PKey, rsa::Rsa};
use thiserror::Error;

use super::certificate::generate_self_signed_certificate;
use crate::config::TlsConfig;

fn internal<E>(error: E) -> KeyMaterialError
where
    E: StdError + Send + Sync + 'static,
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

    let cert_pem =
        generate_self_signed_certificate(&key_pem, domain, &AsymmetricKeyAlgorithm::Rsa2048)?;

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
