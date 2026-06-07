use josekit::{
    JoseError,
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
