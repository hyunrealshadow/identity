use super::*;
use crate::openid_connect::jose::{
    asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk, decode_with_verifier,
    hmac_verifier_from_bytes,
};
use identity_domain::key::PublicJwk;
use identity_domain::openid_connect::CodeChallengeMethod;
use identity_domain::openid_connect::OAuthProtocolVersion;
use josekit::JoseError;
use serde_json::Value;
use subtle::ConstantTimeEq;

pub(crate) fn decode_assertion_with_alg(
    alg: JwsAlgorithm,
    assertion: &str,
    public_key_pem: &[u8],
) -> Result<JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_pem(alg.as_str(), public_key_pem)
        .map_err(|error| assertion_key_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref())
        .map_err(AppError::map_source(TokenErrorCode::AssertionVerifyFailed))
}

pub(crate) fn decode_assertion_with_jwk(
    alg: JwsAlgorithm,
    assertion: &str,
    jwk: &PublicJwk,
) -> Result<JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_public_jwk(alg.as_str(), jwk)
        .map_err(|error| assertion_key_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref())
        .map_err(AppError::map_source(TokenErrorCode::AssertionVerifyFailed))
}

pub(crate) fn decode_assertion_with_hmac_alg(
    alg: JwsAlgorithm,
    assertion: &str,
    secret: &[u8],
) -> Result<JwtPayload, AppError> {
    let verifier = hmac_verifier_from_bytes(alg.as_str(), secret)
        .map_err(|error| assertion_alg_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref())
        .map_err(AppError::map_source(TokenErrorCode::AssertionVerifyFailed))
}

pub(crate) fn client_id_from_assertion(assertion: &str) -> Result<String, AppError> {
    let payload_segment = assertion
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionVerifyFailed))?;

    let payload = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(AppError::map_source(TokenErrorCode::AssertionVerifyFailed))?;

    let payload: Value = serde_json::from_slice(&payload)
        .map_err(AppError::map_source(TokenErrorCode::AssertionVerifyFailed))?;

    payload
        .get("sub")
        .or_else(|| payload.get("iss"))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionSubMissing))
}

fn assertion_key_error(error: JoseError, alg: JwsAlgorithm) -> AppError {
    AppError::from_code(TokenErrorCode::AssertionKeyInvalid)
        .with_param("alg", alg.to_string())
        .with_source(error)
}

fn assertion_alg_error(error: JoseError, alg: JwsAlgorithm) -> AppError {
    AppError::from_code(TokenErrorCode::AssertionAlgUnsupported)
        .with_param("alg", alg.to_string())
        .with_source(error)
}

pub(crate) fn verify_pkce(
    code_challenge: Option<&str>,
    code_challenge_method: Option<CodeChallengeMethod>,
    code_verifier: Option<&str>,
    oauth_version: OAuthProtocolVersion,
) -> Result<(), AppError> {
    let Some(code_challenge) = code_challenge else {
        return if code_verifier.is_some() {
            Err(AppError::from_code(TokenErrorCode::PkceVerifierMismatch))
        } else {
            Ok(())
        };
    };

    let Some(code_verifier) = code_verifier else {
        return Err(AppError::from_code(TokenErrorCode::CodeVerifierRequired));
    };

    let method = code_challenge_method.unwrap_or(CodeChallengeMethod::Plain);
    if oauth_version == OAuthProtocolVersion::V2_1 && method != CodeChallengeMethod::S256 {
        return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported)
            .with_param("code_challenge_method", method.to_string()));
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
        return Err(AppError::from_code(TokenErrorCode::PkceVerifierMismatch));
    }

    Ok(())
}
