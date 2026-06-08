use josekit::{
    JoseError,
    jwe::{
        ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A256KW, JweEncrypter, JweHeader, RSA_OAEP, RSA_OAEP_256,
    },
    jws::{
        ES256, ES256K, ES384, ES512, EdDSA, HS256, HS384, HS512, JwsSigner, JwsVerifier, PS256,
        PS384, PS512, RS256, RS384, RS512,
    },
    jwt::{self, JwtPayload},
};

use crate::domain::key::{JwaSigningAlgorithm, PublicJwk};

pub fn asymmetric_verifier_from_pem(
    alg: &str,
    public_key_pem: &[u8],
) -> Result<Box<dyn JwsVerifier>, JoseError> {
    let jwa: JwaSigningAlgorithm = alg
        .parse()
        .map_err(|_| JoseError::InvalidJwsFormat(anyhow::anyhow!("unsupported JWS alg: {alg}")))?;
    match jwa {
        JwaSigningAlgorithm::Rs256 => RS256
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Rs384 => RS384
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Rs512 => RS512
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Ps256 => PS256
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Ps384 => PS384
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Ps512 => PS512
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Es256 => ES256
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Es384 => ES384
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Es512 => ES512
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::Es256k => ES256K
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        JwaSigningAlgorithm::EdDsa => EdDSA
            .verifier_from_pem(public_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
    }
}

pub fn asymmetric_verifier_from_public_jwk(
    alg: &str,
    jwk: &PublicJwk,
) -> Result<Box<dyn JwsVerifier>, JoseError> {
    let jwk = public_jwk_to_jose(jwk)?;
    match alg {
        "RS256" => RS256
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "RS384" => RS384
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "RS512" => RS512
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "PS256" => PS256
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "PS384" => PS384
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "PS512" => PS512
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "ES256" => ES256
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "ES384" => ES384
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "ES512" => ES512
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "ES256K" => ES256K
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "EdDSA" => EdDSA
            .verifier_from_jwk(&jwk)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        _ => Err(JoseError::InvalidJwsFormat(anyhow::anyhow!(
            "unsupported JWS alg: {alg}"
        ))),
    }
}

pub fn hmac_verifier_from_bytes(
    alg: &str,
    secret: &[u8],
) -> Result<Box<dyn JwsVerifier>, JoseError> {
    match alg {
        "HS256" => HS256
            .verifier_from_bytes(secret)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "HS384" => HS384
            .verifier_from_bytes(secret)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        "HS512" => HS512
            .verifier_from_bytes(secret)
            .map(|value| Box::new(value) as Box<dyn JwsVerifier>),
        _ => Err(JoseError::InvalidJwsFormat(anyhow::anyhow!(
            "unsupported JWS alg: {alg}"
        ))),
    }
}

pub fn asymmetric_signer_from_pem(
    alg: &str,
    private_key_pem: &[u8],
) -> Result<Box<dyn JwsSigner>, JoseError> {
    let jwa: JwaSigningAlgorithm = alg
        .parse()
        .map_err(|_| JoseError::InvalidJwsFormat(anyhow::anyhow!("unsupported JWS alg: {alg}")))?;
    match jwa {
        JwaSigningAlgorithm::Rs256 => RS256
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Rs384 => RS384
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Rs512 => RS512
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Ps256 => PS256
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Ps384 => PS384
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Ps512 => PS512
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Es256 => ES256
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Es384 => ES384
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Es512 => ES512
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::Es256k => ES256K
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
        JwaSigningAlgorithm::EdDsa => EdDSA
            .signer_from_pem(private_key_pem)
            .map(|value| Box::new(value) as Box<dyn JwsSigner>),
    }
}

pub fn decode_with_verifier(
    token: &str,
    verifier: &dyn JwsVerifier,
) -> Result<JwtPayload, JoseError> {
    let (payload, _) = jwt::decode_with_verifier(token, verifier)?;
    Ok(payload)
}

pub fn public_jwk_to_jose(jwk: &PublicJwk) -> Result<josekit::jwk::Jwk, JoseError> {
    let jwk_json =
        serde_json::to_vec(jwk).map_err(|error| JoseError::InvalidJwkFormat(error.into()))?;
    josekit::jwk::Jwk::from_bytes(&jwk_json)
}

pub fn encrypt_compact_with_public_jwk(
    plaintext: &[u8],
    public_jwk: &PublicJwk,
    encryption_alg: &str,
    content_enc: &str,
) -> Result<String, JoseError> {
    let jwk = public_jwk_to_jose(public_jwk)?;
    let encrypter = jwe_encrypter_from_public_jwk(encryption_alg, &jwk)?;
    let mut header = JweHeader::new();
    header.set_algorithm(encryption_alg);
    header.set_content_encryption(content_enc);

    josekit::jwe::serialize_compact(plaintext, &header, &*encrypter)
}

fn jwe_encrypter_from_public_jwk(
    alg: &str,
    jwk: &josekit::jwk::Jwk,
) -> Result<Box<dyn JweEncrypter>, JoseError> {
    match alg {
        "RSA-OAEP" => RSA_OAEP
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "RSA-OAEP-256" => RSA_OAEP_256
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "ECDH-ES" => ECDH_ES
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "ECDH-ES+A128KW" => ECDH_ES_A128KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "ECDH-ES+A256KW" => ECDH_ES_A256KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        _ => Err(JoseError::InvalidJweFormat(anyhow::anyhow!(
            "unsupported JWE alg: {alg}"
        ))),
    }
}
