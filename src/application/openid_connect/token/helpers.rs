use identity_domain::{
    key::PublicJwk,
    openid_connect::{CodeChallengeMethod, OAuthProtocolVersion},
};
use josekit::JoseError;
use serde_json::{Value, from_slice};
use subtle::ConstantTimeEq;

use crate::{
    error::codes::token,
    openid_connect::jose::{
        asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk, decode_with_verifier,
        hmac_verifier_from_bytes,
    },
};

use super::*;

pub(crate) fn decode_assertion_with_alg(
    alg: JwsAlgorithm,
    assertion: &str,
    public_key_pem: &[u8],
) -> Result<JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_pem(alg.as_str(), public_key_pem)
        .map_err(|error| assertion_key_error(error))?;
    decode_with_verifier(assertion, verifier.as_ref())
        .map_err(token::error::AssertionVerifyFailed::map_source())
}

pub(crate) fn decode_assertion_with_jwk(
    alg: JwsAlgorithm,
    assertion: &str,
    jwk: &PublicJwk,
) -> Result<JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_public_jwk(alg.as_str(), jwk)
        .map_err(|error| assertion_key_error(error))?;
    decode_with_verifier(assertion, verifier.as_ref())
        .map_err(token::error::AssertionVerifyFailed::map_source())
}

pub(crate) fn decode_assertion_with_hmac_alg(
    alg: JwsAlgorithm,
    assertion: &str,
    secret: &[u8],
) -> Result<JwtPayload, AppError> {
    let verifier = hmac_verifier_from_bytes(alg.as_str(), secret)
        .map_err(|error| assertion_alg_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref())
        .map_err(token::error::AssertionVerifyFailed::map_source())
}

pub(crate) fn client_id_from_assertion(assertion: &str) -> Result<String, AppError> {
    let payload_segment = assertion
        .split('.')
        .nth(1)
        .ok_or_else(|| token::error::AssertionVerifyFailed.into_error())?;

    let payload = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(token::error::AssertionVerifyFailed::map_source())?;

    let payload: Value =
        from_slice(&payload).map_err(token::error::AssertionVerifyFailed::map_source())?;

    payload
        .get("sub")
        .or_else(|| payload.get("iss"))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| token::error::AssertionSubMissing.into_error())
}

fn assertion_key_error(error: JoseError) -> AppError {
    token::error::AssertionKeyInvalid.with_source(error)
}

fn assertion_alg_error(error: JoseError, alg: JwsAlgorithm) -> AppError {
    token::error::AssertionAlgUnsupported::new(alg).with_source(error)
}

pub(crate) fn verify_pkce(
    code_challenge: Option<&str>,
    code_challenge_method: Option<CodeChallengeMethod>,
    code_verifier: Option<&str>,
    oauth_version: OAuthProtocolVersion,
) -> Result<(), AppError> {
    let Some(code_challenge) = code_challenge else {
        return if code_verifier.is_some() {
            Err(token::error::PkceVerifierMismatch.into_error())
        } else {
            Ok(())
        };
    };

    let Some(code_verifier) = code_verifier else {
        return Err(token::error::CodeVerifierRequired.into_error());
    };

    let method = code_challenge_method.unwrap_or(CodeChallengeMethod::Plain);
    if oauth_version == OAuthProtocolVersion::V2_1 && method != CodeChallengeMethod::S256 {
        return Err(token::error::PkceMethodUnsupported::new(method).into_error());
    }
    let computed = match method {
        CodeChallengeMethod::S256 => {
            let digest = Sha256::digest(code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
        CodeChallengeMethod::Plain => code_verifier.to_owned(),
    };

    if !bool::from(ConstantTimeEq::ct_eq(
        computed.as_bytes(),
        code_challenge.as_bytes(),
    )) {
        return Err(token::error::PkceVerifierMismatch.into_error());
    }

    Ok(())
}
