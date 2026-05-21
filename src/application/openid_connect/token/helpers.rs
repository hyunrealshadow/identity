use super::*;

pub(super) fn decode_assertion_with_alg(
    alg: &str,
    assertion: &str,
    public_key_pem: &[u8],
) -> Result<JwtPayload, AppError> {
    use identity_domain::key::JwaSigningAlgorithm;
    let jwa: JwaSigningAlgorithm = alg
        .parse()
        .map_err(|_| AppError::from_code(TokenErrorCode::AssertionAlgUnsupported))?;
    match jwa {
        JwaSigningAlgorithm::Rs256 => {
            decode_with_verifier(assertion, RS256.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Rs384 => {
            decode_with_verifier(assertion, RS384.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Rs512 => {
            decode_with_verifier(assertion, RS512.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Ps256 => {
            decode_with_verifier(assertion, PS256.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Ps384 => {
            decode_with_verifier(assertion, PS384.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Ps512 => {
            decode_with_verifier(assertion, PS512.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Es256 => {
            decode_with_verifier(assertion, ES256.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Es384 => {
            decode_with_verifier(assertion, ES384.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Es512 => {
            decode_with_verifier(assertion, ES512.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::Es256k => {
            decode_with_verifier(assertion, ES256K.verifier_from_pem(public_key_pem))
        }
        JwaSigningAlgorithm::EdDsa => {
            decode_with_verifier(assertion, EdDSA.verifier_from_pem(public_key_pem))
        }
    }
}

pub(super) fn decode_assertion_with_jwk(
    alg: &str,
    assertion: &str,
    jwk: &identity_domain::key::PublicJwk,
) -> Result<JwtPayload, AppError> {
    let jwk_json = serde_json::to_vec(jwk).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionKeyInvalid).with_source(error)
    })?;
    let jwk = josekit::jwk::Jwk::from_bytes(&jwk_json).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionKeyInvalid).with_source(error)
    })?;

    match alg {
        "RS256" => decode_with_verifier(assertion, RS256.verifier_from_jwk(&jwk)),
        "RS384" => decode_with_verifier(assertion, RS384.verifier_from_jwk(&jwk)),
        "RS512" => decode_with_verifier(assertion, RS512.verifier_from_jwk(&jwk)),
        "PS256" => decode_with_verifier(assertion, PS256.verifier_from_jwk(&jwk)),
        "PS384" => decode_with_verifier(assertion, PS384.verifier_from_jwk(&jwk)),
        "PS512" => decode_with_verifier(assertion, PS512.verifier_from_jwk(&jwk)),
        "ES256" => decode_with_verifier(assertion, ES256.verifier_from_jwk(&jwk)),
        "ES384" => decode_with_verifier(assertion, ES384.verifier_from_jwk(&jwk)),
        "ES512" => decode_with_verifier(assertion, ES512.verifier_from_jwk(&jwk)),
        "ES256K" => decode_with_verifier(assertion, ES256K.verifier_from_jwk(&jwk)),
        "EdDSA" => decode_with_verifier(assertion, EdDSA.verifier_from_jwk(&jwk)),
        _ => Err(AppError::from_code(TokenErrorCode::AssertionAlgUnsupported)),
    }
}

pub(super) fn decode_assertion_with_hmac_alg(
    alg: &str,
    assertion: &str,
    secret: &[u8],
) -> Result<JwtPayload, AppError> {
    match alg {
        "HS256" => decode_with_verifier(assertion, HS256.verifier_from_bytes(secret)),
        "HS384" => decode_with_verifier(assertion, HS384.verifier_from_bytes(secret)),
        "HS512" => decode_with_verifier(assertion, HS512.verifier_from_bytes(secret)),
        _ => Err(AppError::from_code(TokenErrorCode::AssertionAlgUnsupported)),
    }
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
