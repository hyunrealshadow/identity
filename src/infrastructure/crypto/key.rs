use josekit::jwk::{
    Jwk, KeyPair,
    alg::{ec::EcCurve, ecx::EcxCurve, ed::EdCurve},
};
use josekit::jws::{ES256, ES256K, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512};
use openssl::{
    base64::encode_block,
    hash::{MessageDigest, hash},
    pkey::PKey,
    x509::X509,
};

use identity_domain::key::JwaSigningAlgorithm;
use identity_domain::key::{
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
pub(super) fn base64url_encode(bytes: &[u8]) -> String {
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
            AsymmetricKeyAlgorithm::X25519 => generate_x25519_key(),
            AsymmetricKeyAlgorithm::X448 => generate_x448_key(),
        }
    }
}

pub(super) fn generate_rsa_key(bits: usize) -> Result<AsymmetricKeyData, KeyMaterialError> {
    if bits < 2048 {
        return Err(KeyMaterialError::InvalidInput(
            "rsa bits must be at least 2048".to_owned(),
        ));
    }

    let jwk = Jwk::generate_rsa_key(bits as u32).map_err(internal)?;
    build_key_data(&jwk)
}

pub(super) fn generate_p256_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
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

pub(super) fn generate_ed25519_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ed_key(EdCurve::Ed25519).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_ed448_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ed_key(EdCurve::Ed448).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_x25519_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ecx_key(EcxCurve::X25519).map_err(internal)?;
    build_key_data(&jwk)
}

fn generate_x448_key() -> Result<AsymmetricKeyData, KeyMaterialError> {
    let jwk = Jwk::generate_ecx_key(EcxCurve::X448).map_err(internal)?;
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
    if let Ok(private_key) = PKey::private_key_from_pem(private_key_pem.as_bytes())
        && let Ok(rsa) = private_key.rsa()
    {
        let bits = (rsa.size() as usize) * 8;
        return Ok(AsymmetricKeyAlgorithm::Rsa { bits });
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

    if let Ok(key_pair) = josekit::jwk::alg::ecx::EcxKeyPair::from_pem(private_key_pem) {
        return Ok(match key_pair.curve() {
            EcxCurve::X25519 => AsymmetricKeyAlgorithm::X25519,
            EcxCurve::X448 => AsymmetricKeyAlgorithm::X448,
        });
    }

    Err(KeyMaterialError::InvalidInput(
        "unsupported private key format".to_owned(),
    ))
}

pub fn jwa_algorithm_can_sign(jwa: JwaSigningAlgorithm, private_key_pem: &[u8]) -> bool {
    match jwa {
        JwaSigningAlgorithm::Rs256 => RS256.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Rs384 => RS384.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Rs512 => RS512.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Ps256 => PS256.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Ps384 => PS384.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Ps512 => PS512.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Es256 => ES256.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Es384 => ES384.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Es512 => ES512.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::Es256k => ES256K.signer_from_pem(private_key_pem).is_ok(),
        JwaSigningAlgorithm::EdDsa => EdDSA.signer_from_pem(private_key_pem).is_ok(),
    }
}

pub fn public_jwk_from_private_key_pem(
    private_key_pem: &str,
    key_id: Option<&str>,
    certificate_pem: Option<&str>,
) -> Result<Jwk, KeyMaterialError> {
    let alg = primary_jwa_algorithm_for_private_key(private_key_pem)?;
    let mut jwk = public_jwk_from_private_key_pem_without_alg(private_key_pem)?;

    jwk.set_key_use("sig");
    jwk.set_algorithm(alg.as_str());
    if let Some(key_id) = key_id {
        jwk.set_key_id(key_id);
    }

    if let Some(cert_pem) = certificate_pem {
        apply_certificate_params(&mut jwk, cert_pem)?;
    }

    Ok(jwk)
}

pub fn generate_all_jwks_for_key(
    private_key_pem: &str,
    key_id: &str,
    certificate_pem: Option<&str>,
) -> Result<Vec<(String, Jwk)>, KeyMaterialError> {
    let alg = primary_jwa_algorithm_for_private_key(private_key_pem)?;
    let mut base_jwk = public_jwk_from_private_key_pem_without_alg(private_key_pem)?;
    base_jwk.set_key_use("sig");
    base_jwk.set_key_id(key_id);

    if let Some(cert_pem) = certificate_pem {
        apply_certificate_params(&mut base_jwk, cert_pem)?;
    }

    base_jwk.set_algorithm(alg.as_str());

    Ok(vec![(alg.as_str().to_owned(), base_jwk)])
}

fn primary_jwa_algorithm_for_private_key(
    private_key_pem: &str,
) -> Result<JwaSigningAlgorithm, KeyMaterialError> {
    if let Some(alg) = primary_rsa_pss_jwa_algorithm(private_key_pem)? {
        return Ok(alg);
    }

    let algorithm = infer_algorithm_from_private_key_pem(private_key_pem)?;
    Ok(JwaSigningAlgorithm::primary_for_key_type(&algorithm))
}

fn primary_rsa_pss_jwa_algorithm(
    private_key_pem: &str,
) -> Result<Option<JwaSigningAlgorithm>, KeyMaterialError> {
    if josekit::jwk::alg::rsapss::RsaPssKeyPair::from_pem(private_key_pem, None, None, None)
        .is_err()
    {
        return Ok(None);
    }

    let pem = private_key_pem.as_bytes();
    if PS256.signer_from_pem(pem).is_ok() {
        return Ok(Some(JwaSigningAlgorithm::Ps256));
    }
    if PS384.signer_from_pem(pem).is_ok() {
        return Ok(Some(JwaSigningAlgorithm::Ps384));
    }
    if PS512.signer_from_pem(pem).is_ok() {
        return Ok(Some(JwaSigningAlgorithm::Ps512));
    }

    Err(KeyMaterialError::InvalidInput(
        "unsupported rsa-pss parameters".to_owned(),
    ))
}

fn public_jwk_from_private_key_pem_without_alg(
    private_key_pem: &str,
) -> Result<Jwk, KeyMaterialError> {
    if let Ok(key_pair) =
        josekit::jwk::alg::rsapss::RsaPssKeyPair::from_pem(private_key_pem, None, None, None)
    {
        return Ok(key_pair.to_jwk_public_key());
    }

    if let Ok(key_pair) = josekit::jwk::alg::rsa::RsaKeyPair::from_pem(private_key_pem) {
        return Ok(key_pair.to_jwk_public_key());
    }

    if let Ok(key_pair) = josekit::jwk::alg::ec::EcKeyPair::from_pem(private_key_pem, None) {
        return Ok(key_pair.to_jwk_public_key());
    }

    if let Ok(key_pair) = josekit::jwk::alg::ed::EdKeyPair::from_pem(private_key_pem) {
        return Ok(key_pair.to_jwk_public_key());
    }

    if let Ok(key_pair) = josekit::jwk::alg::ecx::EcxKeyPair::from_pem(private_key_pem) {
        return Ok(key_pair.to_jwk_public_key());
    }

    Err(KeyMaterialError::InvalidInput(
        "unsupported private key format".to_owned(),
    ))
}

fn export_private_pem(jwk: &Jwk) -> Result<String, KeyMaterialError> {
    export_pem(jwk, true)
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
                "X25519" | "X448" => {
                    let key_pair =
                        josekit::jwk::alg::ecx::EcxKeyPair::from_jwk(jwk).map_err(internal)?;
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
