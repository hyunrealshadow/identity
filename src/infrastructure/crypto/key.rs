use josekit::jwk::{
    Jwk, KeyPair,
    alg::{ec::EcCurve, ed::EdCurve},
};
use openssl::pkey::PKey;

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
