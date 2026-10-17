//! Request Object decryption, signature verification, and verified payload decoding.

use super::super::AuthorizeService;
use crate::error::{AppError, codes::authorize::AuthorizeErrorCode};
use crate::openid_connect::jose::{
    REQUEST_OBJECT_CONTENT_ENCRYPTION_ALGORITHMS, REQUEST_OBJECT_ENCRYPTION_ALGORITHMS,
    asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk, decode_with_verifier,
    decrypt_compact_with_private_pem,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_domain::{
    key::{JwsAlgorithm, KeyData, PublicJwk},
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectCredentialData, OpenIdConnectCredentialType,
        model::claim::JwtClaimNames,
    },
};
use josekit::{jwe::JweHeader, jwt};
use serde_json::{Map, Value};

impl AuthorizeService {
    pub(in super::super) async fn parse_request_object_payload(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
    ) -> Result<Value, AppError> {
        let raw = if raw.split('.').count() == 5 {
            self.decrypt_request_object(client, raw).await?
        } else {
            raw.to_owned()
        };

        let header = jwt::decode_header(&raw).map_err(AppError::map_source(
            AuthorizeErrorCode::RequestObjectHeaderInvalid,
        ))?;

        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none")
            .parse::<JwsAlgorithm>()
            .map_err(AppError::map_source(
                AuthorizeErrorCode::RequestObjectVerifyFailed,
            ))?;
        if let Some(registered_algorithms) = &client.metadata().request_object_signing_algs
            && !registered_algorithms.contains(&algorithm)
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectVerifyFailed,
            ));
        }

        let payload = match algorithm {
            JwsAlgorithm::None => jwt::decode_unsecured(&raw)
                .map(|(payload, _)| payload)
                .map_err(AppError::map_source(
                    AuthorizeErrorCode::RequestObjectPayloadInvalid,
                ))?,
            _ => {
                self.verify_signed_request_object(client, &raw, algorithm)
                    .await?
            }
        };

        if payload.claim("request").is_some() || payload.claim("request_uri").is_some() {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectPayloadInvalid,
            ));
        }
        let mut value = Map::new();
        for claim in [
            "response_type",
            "response_mode",
            "client_id",
            "redirect_uri",
            "scope",
            "resource",
            "state",
            "nonce",
            "display",
            "prompt",
            "max_age",
            "ui_locales",
            "claims_locales",
            "id_token_hint",
            "login_hint",
            "acr_values",
            "claims",
            "code_challenge",
            "code_challenge_method",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
        ] {
            if let Some(claim_value) = payload.claim(claim) {
                value.insert(claim.to_string(), claim_value.clone());
            }
        }

        Ok(Value::Object(value))
    }

    async fn decrypt_request_object(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
    ) -> Result<String, AppError> {
        let protected = raw
            .split('.')
            .next()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestObjectHeaderInvalid))?;
        let protected = URL_SAFE_NO_PAD
            .decode(protected)
            .map_err(AppError::map_source(
                AuthorizeErrorCode::RequestObjectHeaderInvalid,
            ))?;
        let header = JweHeader::from_bytes(&protected).map_err(AppError::map_source(
            AuthorizeErrorCode::RequestObjectHeaderInvalid,
        ))?;
        let algorithm = header
            .algorithm()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestObjectHeaderInvalid))?;
        let content_encryption = header
            .content_encryption()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestObjectHeaderInvalid))?;

        if !REQUEST_OBJECT_ENCRYPTION_ALGORITHMS.contains(&algorithm)
            || !REQUEST_OBJECT_CONTENT_ENCRYPTION_ALGORITHMS.contains(&content_encryption)
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectEncryptionUnsupported,
            ));
        }
        if client
            .metadata()
            .request_object_encryption_algs
            .as_ref()
            .is_some_and(|registered| !registered.iter().any(|value| value.as_str() == algorithm))
            || client
                .metadata()
                .request_object_encryption_encs
                .as_ref()
                .is_some_and(|registered| {
                    !registered
                        .iter()
                        .any(|value| value.as_str() == content_encryption)
                })
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectEncryptionUnsupported,
            ));
        }

        let keys = if let Some(kid) = header.key_id() {
            let bindings = self
                .key_jwk_repo
                .list_active()
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?;
            let binding = bindings
                .into_iter()
                .find(|binding| binding.jwk.key_id() == Some(kid))
                .ok_or_else(|| {
                    AppError::from_code(AuthorizeErrorCode::RequestObjectEncryptionUnsupported)
                })?;
            self.key_repo
                .find_by_oid(binding.key_oid)
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?
                .into_iter()
                .collect()
        } else {
            self.key_repo
                .list_active_asymmetric()
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?
        };

        for key in &keys {
            let KeyData::Asymmetric(data) = &key.data else {
                continue;
            };
            if let Ok((bytes, authenticated_header)) =
                decrypt_compact_with_private_pem(raw, data.private_key.as_bytes(), algorithm)
                && authenticated_header.algorithm() == Some(algorithm)
                && authenticated_header.content_encryption() == Some(content_encryption)
                && let Ok(payload) = String::from_utf8(bytes)
            {
                return Ok(payload);
            }
        }

        Err(AppError::from_code(
            AuthorizeErrorCode::RequestObjectEncryptionUnsupported,
        ))
    }

    async fn verify_signed_request_object(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
        algorithm: JwsAlgorithm,
    ) -> Result<jwt::JwtPayload, AppError> {
        let credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(AppError::map_source(
                AuthorizeErrorCode::CredentialLookupFailed,
            ))?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientPublicKey { public_key, jwk } =
                credential.data
            {
                if let Some(jwk) = jwk
                    && let Ok(payload) = decode_request_object_with_jwk(raw, algorithm, &jwk)
                {
                    return Ok(payload);
                }
                if let Ok(payload) = decode_request_object(raw, algorithm, public_key.as_bytes()) {
                    return Ok(payload);
                }
            }
        }

        let jwks_credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientJsonWebKeySet,
            )
            .await
            .map_err(AppError::map_source(
                AuthorizeErrorCode::CredentialLookupFailed,
            ))?;

        for credential in jwks_credentials {
            if let OpenIdConnectCredentialData::ClientJsonWebKeySet {
                public_keys, jwks, ..
            } = credential.data
            {
                for jwk in jwks {
                    if let Ok(payload) = decode_request_object_with_jwk(raw, algorithm, &jwk) {
                        return Ok(payload);
                    }
                }
                for public_key in public_keys {
                    if let Ok(payload) =
                        decode_request_object(raw, algorithm, public_key.as_bytes())
                    {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(AppError::from_code(
            AuthorizeErrorCode::RequestObjectVerifyFailed,
        ))
    }
}

fn decode_request_object_with_jwk(
    raw: &str,
    alg: JwsAlgorithm,
    jwk: &PublicJwk,
) -> Result<jwt::JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_public_jwk(alg.as_str(), jwk).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::RequestObjectKeyInvalid)
            .with_param("alg", alg.to_string())
            .with_source(error)
    })?;
    decode_with_verifier(raw, verifier.as_ref()).map_err(AppError::map_source(
        AuthorizeErrorCode::RequestObjectVerifyFailed,
    ))
}

fn decode_request_object(
    raw: &str,
    alg: JwsAlgorithm,
    public_key_pem: &[u8],
) -> Result<jwt::JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_pem(alg.as_str(), public_key_pem).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::RequestObjectKeyInvalid)
            .with_param("alg", alg.to_string())
            .with_source(error)
    })?;
    decode_with_verifier(raw, verifier.as_ref()).map_err(AppError::map_source(
        AuthorizeErrorCode::RequestObjectVerifyFailed,
    ))
}
