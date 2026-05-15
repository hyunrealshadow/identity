use josekit::JoseError;
use josekit::jwe::{
    ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A256KW, JweDecrypter, JweEncrypter, JweHeader, RSA_OAEP,
    RSA_OAEP_256,
};

use identity_domain::key::PublicJwk;

#[derive(Debug, thiserror::Error)]
pub enum JweError {
    #[error("unsupported encryption algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("encryption failed: {0}")]
    EncryptFailed(#[source] JoseError),
    #[error("decryption failed: {0}")]
    DecryptFailed(#[source] JoseError),
    #[error("invalid JWK for encryption: {0}")]
    InvalidJwk(String),
}

fn public_jwk_to_josekit(jwk: &PublicJwk) -> Result<josekit::jwk::Jwk, JweError> {
    let value = serde_json::to_value(jwk).map_err(|e| JweError::InvalidJwk(e.to_string()))?;
    let json = value.to_string();
    josekit::jwk::Jwk::from_bytes(json.as_bytes()).map_err(|e| JweError::InvalidJwk(e.to_string()))
}

pub fn build_encrypter(jwk: &PublicJwk, alg: &str) -> Result<Box<dyn JweEncrypter>, JweError> {
    let josekit_jwk = public_jwk_to_josekit(jwk)?;
    match alg {
        "RSA-OAEP" => Ok(Box::new(
            RSA_OAEP
                .encrypter_from_jwk(&josekit_jwk)
                .map_err(|e| JweError::InvalidJwk(e.to_string()))?,
        )),
        "RSA-OAEP-256" => Ok(Box::new(
            RSA_OAEP_256
                .encrypter_from_jwk(&josekit_jwk)
                .map_err(|e| JweError::InvalidJwk(e.to_string()))?,
        )),
        "ECDH-ES" => Ok(Box::new(
            ECDH_ES
                .encrypter_from_jwk(&josekit_jwk)
                .map_err(|e| JweError::InvalidJwk(e.to_string()))?,
        )),
        "ECDH-ES+A128KW" => Ok(Box::new(
            ECDH_ES_A128KW
                .encrypter_from_jwk(&josekit_jwk)
                .map_err(|e| JweError::InvalidJwk(e.to_string()))?,
        )),
        "ECDH-ES+A256KW" => Ok(Box::new(
            ECDH_ES_A256KW
                .encrypter_from_jwk(&josekit_jwk)
                .map_err(|e| JweError::InvalidJwk(e.to_string()))?,
        )),
        _ => Err(JweError::UnsupportedAlgorithm(alg.to_owned())),
    }
}

pub fn build_decrypter(
    private_key_pem: &str,
    alg: &str,
) -> Result<Box<dyn JweDecrypter>, JweError> {
    let pem = private_key_pem.as_bytes();
    match alg {
        "RSA-OAEP" => Ok(Box::new(
            RSA_OAEP
                .decrypter_from_pem(pem)
                .map_err(|e| JweError::DecryptFailed(e))?,
        )),
        "RSA-OAEP-256" => Ok(Box::new(
            RSA_OAEP_256
                .decrypter_from_pem(pem)
                .map_err(|e| JweError::DecryptFailed(e))?,
        )),
        "ECDH-ES" => Ok(Box::new(
            ECDH_ES
                .decrypter_from_pem(pem)
                .map_err(|e| JweError::DecryptFailed(e))?,
        )),
        "ECDH-ES+A128KW" => Ok(Box::new(
            ECDH_ES_A128KW
                .decrypter_from_pem(pem)
                .map_err(|e| JweError::DecryptFailed(e))?,
        )),
        "ECDH-ES+A256KW" => Ok(Box::new(
            ECDH_ES_A256KW
                .decrypter_from_pem(pem)
                .map_err(|e| JweError::DecryptFailed(e))?,
        )),
        _ => Err(JweError::UnsupportedAlgorithm(alg.to_owned())),
    }
}

pub fn encrypt_jwe(
    payload: &[u8],
    encrypter: &dyn JweEncrypter,
    header: &JweHeader,
) -> Result<String, JweError> {
    josekit::jwe::serialize_compact(payload, header, encrypter).map_err(JweError::EncryptFailed)
}

pub fn decrypt_jwe(
    encoded: &str,
    decrypter: &dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JweError> {
    josekit::jwe::deserialize_compact(encoded, decrypter).map_err(JweError::DecryptFailed)
}
