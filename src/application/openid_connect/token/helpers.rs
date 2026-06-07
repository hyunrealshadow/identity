use super::*;
use crate::openid_connect::jose::{
    asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk, decode_with_verifier,
    hmac_verifier_from_bytes,
};

pub(super) fn decode_assertion_with_alg(
    alg: &str,
    assertion: &str,
    public_key_pem: &[u8],
) -> Result<JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_pem(alg, public_key_pem)
        .map_err(|error| assertion_key_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref()).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })
}

pub(super) fn decode_assertion_with_jwk(
    alg: &str,
    assertion: &str,
    jwk: &identity_domain::key::PublicJwk,
) -> Result<JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_public_jwk(alg, jwk)
        .map_err(|error| assertion_key_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref()).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })
}

pub(super) fn decode_assertion_with_hmac_alg(
    alg: &str,
    assertion: &str,
    secret: &[u8],
) -> Result<JwtPayload, AppError> {
    let verifier =
        hmac_verifier_from_bytes(alg, secret).map_err(|error| assertion_alg_error(error, alg))?;
    decode_with_verifier(assertion, verifier.as_ref()).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })
}

pub(super) fn client_id_from_assertion(assertion: &str) -> Result<String, AppError> {
    let payload_segment = assertion
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionVerifyFailed))?;

    let payload = URL_SAFE_NO_PAD.decode(payload_segment).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })?;

    let payload: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })?;

    payload
        .get("sub")
        .or_else(|| payload.get("iss"))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionSubMissing))
}

fn assertion_key_error(error: josekit::JoseError, alg: &str) -> AppError {
    AppError::from_code(TokenErrorCode::AssertionKeyInvalid)
        .with_param("alg", alg)
        .with_source(error)
}

fn assertion_alg_error(error: josekit::JoseError, alg: &str) -> AppError {
    AppError::from_code(TokenErrorCode::AssertionAlgUnsupported)
        .with_param("alg", alg)
        .with_source(error)
}

pub(super) fn verify_pkce(
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    code_verifier: Option<&str>,
) -> Result<(), AppError> {
    let Some(code_challenge) = code_challenge else {
        return Ok(());
    };

    let Some(code_verifier) = code_verifier else {
        return Err(AppError::from_code(TokenErrorCode::CodeVerifierRequired));
    };

    let method = code_challenge_method.unwrap_or("plain");
    let computed = match method {
        "plain" => code_verifier.to_string(),
        "S256" => {
            let digest = Sha256::digest(code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
        _ => {
            return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported)
                .with_param("code_challenge_method", method));
        }
    };

    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        computed.as_bytes(),
        code_challenge.as_bytes(),
    )) {
        return Err(AppError::from_code(TokenErrorCode::PkceVerifierMismatch));
    }

    Ok(())
}
