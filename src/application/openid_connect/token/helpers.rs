use super::*;

pub(super) fn decode_assertion_with_alg(
    alg: &str,
    assertion: &str,
    public_key_pem: &[u8],
) -> Result<JwtPayload, AppError> {
    match alg {
        "RS256" => decode_with_verifier(assertion, RS256.verifier_from_pem(public_key_pem)),
        "RS384" => decode_with_verifier(assertion, RS384.verifier_from_pem(public_key_pem)),
        "RS512" => decode_with_verifier(assertion, RS512.verifier_from_pem(public_key_pem)),
        "ES256" => decode_with_verifier(assertion, ES256.verifier_from_pem(public_key_pem)),
        "ES384" => decode_with_verifier(assertion, ES384.verifier_from_pem(public_key_pem)),
        "ES512" => decode_with_verifier(assertion, ES512.verifier_from_pem(public_key_pem)),
        "ES256K" => decode_with_verifier(assertion, ES256K.verifier_from_pem(public_key_pem)),
        "EdDSA" => decode_with_verifier(assertion, EdDSA.verifier_from_pem(public_key_pem)),
        _ => Err(AppError::from_code(TokenErrorCode::AssertionAlgUnsupported)),
    }
}

fn decode_with_verifier<V>(
    assertion: &str,
    verifier: Result<V, josekit::JoseError>,
) -> Result<JwtPayload, AppError>
where
    V: josekit::jws::JwsVerifier,
{
    let verifier = verifier.map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionKeyInvalid).with_source(error)
    })?;
    let (payload, _) = jwt::decode_with_verifier(assertion, &verifier).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })?;
    Ok(payload)
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
            return Err(AppError::from_code(TokenErrorCode::PkceMethodUnsupported));
        }
    };

    if computed != code_challenge {
        return Err(AppError::from_code(TokenErrorCode::PkceVerifierMismatch));
    }

    Ok(())
}

pub(super) fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
