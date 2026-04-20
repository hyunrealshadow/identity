use josekit::jwk::{
    Jwk, KeyPair,
    alg::{ec::EcCurve, ed::EdCurve},
};
use openssl::{
    base64::encode_block,
    hash::{MessageDigest, hash},
    pkey::PKey,
    x509::X509,
};

use crate::domain::key::{
    generator::{AsymmetricKeyGenerator, AsymmetricKeySpec, KeyMaterialError},
    model::{AsymmetricKeyAlgorithm, AsymmetricKeyData},
};

fn internal<E>(error: E) -> KeyMaterialError
where
    E: std::error::Error + Send + Sync + 'static,
{
    KeyMaterialError::Internal(Box::new(error))
}

/// Encodes bytes as base64url (RFC 4648 §5): URL-safe alphabet, no padding.
fn base64url_encode(bytes: &[u8]) -> String {
    encode_block(bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "")
}

fn apply_certificate_params(jwk: &mut Jwk, cert_pem: &str) -> Result<(), KeyMaterialError> {
    let x509 = X509::from_pem(cert_pem.as_bytes()).map_err(internal)?;
    let der = x509.to_der().map_err(internal)?;

    // x5c: base64-standard-encoded DER, wrapped in a JSON array (single cert)
    let x5c_value = encode_block(&der);
    jwk.set_parameter("x5c", Some(serde_json::json!([x5c_value])))
        .map_err(internal)?;

    // x5t: SHA-1 thumbprint, base64url-encoded
    let sha1_digest = hash(MessageDigest::sha1(), &der).map_err(internal)?;
    jwk.set_parameter(
        "x5t",
        Some(serde_json::json!(base64url_encode(&sha1_digest))),
    )
    .map_err(internal)?;

    // x5t#S256: SHA-256 thumbprint, base64url-encoded
    let sha256_digest = hash(MessageDigest::sha256(), &der).map_err(internal)?;
    jwk.set_parameter(
        "x5t#S256",
        Some(serde_json::json!(base64url_encode(&sha256_digest))),
    )
    .map_err(internal)?;

    Ok(())
}

pub struct AsymmetricKeyGeneratorImpl;

impl AsymmetricKeyGenerator for AsymmetricKeyGeneratorImpl {
    fn generate(&self, spec: &AsymmetricKeySpec) -> Result<AsymmetricKeyData, KeyMaterialError> {
        match spec.algorithm {
            AsymmetricKeyAlgorithm::Rsa { bits } => generate_rsa_key(bits),
            AsymmetricKeyAlgorithm::EcdsaP256 => generate_p256_key(),
            AsymmetricKeyAlgorithm::EcdsaP384 => generate_p384_key(),
            AsymmetricKeyAlgorithm::EcdsaP521 => generate_p521_key(),
            AsymmetricKeyAlgorithm::EcdsaSecp256k1 => generate_k256_key(),
            AsymmetricKeyAlgorithm::Ed25519 => generate_ed25519_key(),
            AsymmetricKeyAlgorithm::Ed448 => generate_ed448_key(),
        }
    }
}

fn generate_rsa_key(bits: usize) -> Result<AsymmetricKeyData, KeyMaterialError> {
    if bits < 2048 {
        return Err(KeyMaterialError::InvalidInput(
            "rsa bits must be at least 2048".to_owned(),
        ));
    }

    let jwk = Jwk::generate_rsa_key(bits as u32).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_p256_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ec_key(EcCurve::P256).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_p384_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ec_key(EcCurve::P384).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_p521_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ec_key(EcCurve::P521).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_k256_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ec_key(EcCurve::Secp256k1).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_ed25519_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ed_key(EdCurve::Ed25519).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_ed448_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ed_key(EdCurve::Ed448).map_err(internal)?;
    build_key_data(&jwk)
}

fn build_key_data(jwk: &Jwk) -> Result<AsymmetricKeyData, KeyMaterialError> {
    let private_key = export_private_pem(jwk)?;
    let public_key = export_public_pem(jwk)?;

    Ok(AsymmetricKeyData {
        private_key,
        public_key,
        certificate: None,
    })
}

pub fn infer_algorithm_from_private_key_pem(
    private_key_pem: &str,
) -> Result<AsymmetricKeyAlgorithm, KeyMaterialError> {
    if let Ok(private_key) = PKey::private_key_from_pem(private_key_pem.as_bytes()) {
        if let Ok(rsa) = private_key.rsa() {
            let bits = (rsa.size() as usize) * 8;
            return Ok(AsymmetricKeyAlgorithm::Rsa { bits });
        }
    }

    if let Ok(key_pair) = josekit::jwk::alg::ec::EcKeyPair::from_pem(private_key_pem, None) {
        return Ok(match key_pair.curve() {
            EcCurve::P256 => AsymmetricKeyAlgorithm::EcdsaP256,
            EcCurve::P384 => AsymmetricKeyAlgorithm::EcdsaP384,
            EcCurve::P521 => AsymmetricKeyAlgorithm::EcdsaP521,
            EcCurve::Secp256k1 => AsymmetricKeyAlgorithm::EcdsaSecp256k1,
        });
    }

    if let Ok(key_pair) = josekit::jwk::alg::ed::EdKeyPair::from_pem(private_key_pem) {
        return Ok(match key_pair.curve() {
            EdCurve::Ed25519 => AsymmetricKeyAlgorithm::Ed25519,
            EdCurve::Ed448 => AsymmetricKeyAlgorithm::Ed448,
        });
    }

    Err(KeyMaterialError::InvalidInput(
        "unsupported private key format".to_owned(),
    ))
}

pub fn public_jwk_from_private_key_pem(
    private_key_pem: &str,
    key_id: Option<&str>,
    certificate_pem: Option<&str>,
) -> Result<Jwk, KeyMaterialError> {
    let algorithm = infer_algorithm_from_private_key_pem(private_key_pem)?;
    let mut jwk = match algorithm {
        AsymmetricKeyAlgorithm::Rsa { .. } => {
            josekit::jwk::alg::rsa::RsaKeyPair::from_pem(private_key_pem)
                .map_err(internal)?
                .to_jwk_public_key()
        }
        AsymmetricKeyAlgorithm::EcdsaP256
        | AsymmetricKeyAlgorithm::EcdsaP384
        | AsymmetricKeyAlgorithm::EcdsaP521
        | AsymmetricKeyAlgorithm::EcdsaSecp256k1 => {
            josekit::jwk::alg::ec::EcKeyPair::from_pem(private_key_pem, None)
                .map_err(internal)?
                .to_jwk_public_key()
        }
        AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => {
            josekit::jwk::alg::ed::EdKeyPair::from_pem(private_key_pem)
                .map_err(internal)?
                .to_jwk_public_key()
        }
    };

    jwk.set_key_use("sig");
    jwk.set_algorithm(jwa_algorithm_name(&algorithm));
    if let Some(key_id) = key_id {
        jwk.set_key_id(key_id);
    }

    if let Some(cert_pem) = certificate_pem {
        apply_certificate_params(&mut jwk, cert_pem)?;
    }

    Ok(jwk)
}

fn jwa_algorithm_name(algorithm: &AsymmetricKeyAlgorithm) -> &'static str {
    match algorithm {
        AsymmetricKeyAlgorithm::Rsa { bits } if *bits >= 4096 => "RS512",
        AsymmetricKeyAlgorithm::Rsa { bits } if *bits >= 3072 => "RS384",
        AsymmetricKeyAlgorithm::Rsa { .. } => "RS256",
        AsymmetricKeyAlgorithm::EcdsaP256 => "ES256",
        AsymmetricKeyAlgorithm::EcdsaP384 => "ES384",
        AsymmetricKeyAlgorithm::EcdsaP521 => "ES512",
        AsymmetricKeyAlgorithm::EcdsaSecp256k1 => "ES256K",
        AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => "EdDSA",
    }
}

fn export_private_pem(jwk: &Jwk) -> Result<String, KeyMaterialError> {
    export_pem(jwk, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generates a minimal RSA 2048 key PEM and a self-signed cert PEM for testing.
    fn test_rsa_key_and_cert() -> (String, String) {
        use crate::domain::key::model::AsymmetricKeyAlgorithm;
        use crate::infrastructure::crypto::certificate::generate_self_signed_certificate;

        let data = generate_rsa_key(2048).unwrap();
        let cert = generate_self_signed_certificate(
            &data.private_key,
            "test.example.com",
            &AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
        )
        .unwrap();
        (data.private_key, cert)
    }

    #[test]
    fn jwk_without_certificate_has_no_x5_fields() {
        let (private_key, _cert) = test_rsa_key_and_cert();
        let jwk = public_jwk_from_private_key_pem(&private_key, None, None).unwrap();
        assert!(jwk.parameter("x5c").is_none());
        assert!(jwk.parameter("x5t").is_none());
        assert!(jwk.parameter("x5t#S256").is_none());
    }

    #[test]
    fn jwk_with_certificate_has_x5c_x5t_x5t_s256() {
        let (private_key, cert) = test_rsa_key_and_cert();
        let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert)).unwrap();

        // x5c must be a non-empty array
        let x5c = jwk.parameter("x5c").expect("x5c missing");
        assert!(x5c.is_array(), "x5c must be a JSON array");
        let arr = x5c.as_array().unwrap();
        assert_eq!(arr.len(), 1, "x5c must have exactly one element");
        assert!(arr[0].is_string(), "x5c[0] must be a string");

        // x5t must be a non-empty string
        let x5t = jwk.parameter("x5t").expect("x5t missing");
        assert!(x5t.is_string());
        assert!(!x5t.as_str().unwrap().is_empty());

        // x5t#S256 must be a non-empty string
        let x5t_s256 = jwk.parameter("x5t#S256").expect("x5t#S256 missing");
        assert!(x5t_s256.is_string());
        assert!(!x5t_s256.as_str().unwrap().is_empty());
    }

    #[test]
    fn x5t_s256_matches_sha256_of_der() {
        use openssl::hash::{MessageDigest, hash};
        use openssl::x509::X509;

        let (private_key, cert_pem) = test_rsa_key_and_cert();
        let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert_pem)).unwrap();

        // Independently compute expected x5t#S256
        let x509 = X509::from_pem(cert_pem.as_bytes()).unwrap();
        let der = x509.to_der().unwrap();
        let digest = hash(MessageDigest::sha256(), &der).unwrap();
        let expected = base64url_encode(&digest);

        let actual = jwk
            .parameter("x5t#S256")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(actual, expected);
    }

    #[test]
    fn x5t_matches_sha1_of_der() {
        use openssl::hash::{MessageDigest, hash};
        use openssl::x509::X509;

        let (private_key, cert_pem) = test_rsa_key_and_cert();
        let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert_pem)).unwrap();

        let x509 = X509::from_pem(cert_pem.as_bytes()).unwrap();
        let der = x509.to_der().unwrap();
        let digest = hash(MessageDigest::sha1(), &der).unwrap();
        let expected = base64url_encode(&digest);

        let actual = jwk.parameter("x5t").unwrap().as_str().unwrap().to_owned();
        assert_eq!(actual, expected);
    }

    #[test]
    fn x5c_matches_base64_standard_of_der() {
        use openssl::base64::encode_block;
        use openssl::x509::X509;

        let (private_key, cert_pem) = test_rsa_key_and_cert();
        let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert_pem)).unwrap();

        let x509 = X509::from_pem(cert_pem.as_bytes()).unwrap();
        let der = x509.to_der().unwrap();
        let expected = encode_block(&der);

        let actual = jwk.parameter("x5c").unwrap().as_array().unwrap()[0]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(actual, expected);
    }
}

fn export_public_pem(jwk: &Jwk) -> Result<String, KeyMaterialError> {
    export_pem(jwk, false)
}

fn export_pem(jwk: &Jwk, private: bool) -> Result<String, KeyMaterialError> {
    let pem = match jwk.key_type() {
        "RSA" => {
            let key_pair = josekit::jwk::alg::rsa::RsaKeyPair::from_jwk(jwk).map_err(internal)?;
            if private {
                key_pair.to_pem_private_key()
            } else {
                key_pair.to_pem_public_key()
            }
        }
        "EC" => {
            let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(jwk).map_err(internal)?;
            if private {
                key_pair.to_pem_private_key()
            } else {
                key_pair.to_pem_public_key()
            }
        }
        "OKP" => {
            let curve = jwk.curve().ok_or_else(|| {
                KeyMaterialError::InvalidInput("okp key is missing curve metadata".to_owned())
            })?;

            match curve {
                "Ed25519" | "Ed448" => {
                    let key_pair =
                        josekit::jwk::alg::ed::EdKeyPair::from_jwk(jwk).map_err(internal)?;
                    if private {
                        key_pair.to_pem_private_key()
                    } else {
                        key_pair.to_pem_public_key()
                    }
                }
                _ => {
                    return Err(KeyMaterialError::InvalidInput(format!(
                        "unsupported okp curve: {curve}"
                    )));
                }
            }
        }
        key_type => {
            return Err(KeyMaterialError::InvalidInput(format!(
                "unsupported jwk key type: {key_type}"
            )));
        }
    };

    String::from_utf8(pem).map_err(internal)
}
