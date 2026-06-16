use super::*;
use crate::openid_connect::jose::{
    asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk, decode_with_verifier,
};
#[cfg(test)]
use crate::openid_connect::remote::fetchable_url;
use crate::openid_connect::remote::{
    DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchError, RemoteUrlError,
    fetch_https_public_document, validate_https_public_url,
};

impl AuthorizeService {
    pub(super) async fn resolve_request_object(
        &self,
        client: &OpenIdConnectClient,
        params: &AuthorizationRequestParams,
    ) -> Result<Option<String>, AppError> {
        if let Some(request) = params.request.clone() {
            return Ok(Some(request));
        }

        if let Some(request_uri) = params.request_uri.clone() {
            let request_uri = Url::parse(&request_uri).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestUriInvalid).with_source(error)
            })?;
            self.validate_request_uri(client, &request_uri)?;
            let raw_request_object = self.fetch_request_object(&request_uri).await?;
            return Ok(Some(raw_request_object));
        }

        Ok(None)
    }

    fn validate_request_uri(
        &self,
        client: &OpenIdConnectClient,
        request_uri: &Url,
    ) -> Result<(), AppError> {
        validate_https_public_url(request_uri).map_err(|error| match error {
            RemoteUrlError::NotHttps => AppError::from_code(AuthorizeErrorCode::RequestUriNotHttps),
            RemoteUrlError::UnsafeHost => {
                AppError::from_code(AuthorizeErrorCode::RequestUriUnsafeHost)
            }
        })?;

        let registered = client
            .metadata()
            .request_uris
            .as_ref()
            .map(|uris| uris.iter().any(|uri| uri == request_uri))
            .unwrap_or(false);

        if !registered {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestUriNotRegistered,
            ));
        }

        Ok(())
    }

    pub(super) async fn fetch_request_object(&self, request_uri: &Url) -> Result<String, AppError> {
        let body = fetch_https_public_document(
            &self.http_client,
            request_uri,
            DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        )
        .await
        .map_err(map_request_uri_fetch_error)?;

        String::from_utf8(body).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestUriReadFailed).with_source(error)
        })
    }

    pub(super) async fn parse_request_object_payload(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
    ) -> Result<serde_json::Value, AppError> {
        let raw = if raw.split('.').count() == 5 {
            self.decrypt_request_object(raw).await?
        } else {
            raw.to_owned()
        };

        let header = jwt::decode_header(&raw).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestObjectHeaderInvalid).with_source(error)
        })?;

        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        if let Some(registered_algorithm) = client.metadata().request_object_signing_alg.as_deref()
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectVerifyFailed,
            ));
        }

        let payload = match algorithm {
            "none" => {
                let parts: Vec<&str> = raw.split('.').collect();
                if parts.len() < 2 {
                    return Err(AppError::from_code(
                        AuthorizeErrorCode::RequestObjectHeaderInvalid,
                    ));
                }
                let decoded = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::RequestObjectPayloadInvalid)
                        .with_source(error)
                })?;
                let payload_value: serde_json::Value =
                    serde_json::from_slice(&decoded).map_err(|error| {
                        AppError::from_code(AuthorizeErrorCode::RequestObjectPayloadInvalid)
                            .with_source(error)
                    })?;
                let mut jwt_payload = jwt::JwtPayload::new();
                if let serde_json::Value::Object(map) = payload_value {
                    for (k, v) in map {
                        jwt_payload.set_claim(&k, Some(v)).map_err(|error| {
                            AppError::from_code(AuthorizeErrorCode::RequestObjectPayloadInvalid)
                                .with_source(error)
                        })?;
                    }
                }
                jwt_payload
            }
            _ => {
                self.verify_signed_request_object(client, &raw, algorithm)
                    .await?
            }
        };

        let mut value = serde_json::Map::new();
        for claim in [
            "response_type",
            "response_mode",
            "client_id",
            "redirect_uri",
            "scope",
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

        Ok(serde_json::Value::Object(value))
    }

    async fn decrypt_request_object(&self, raw: &str) -> Result<String, AppError> {
        use josekit::jwe::{
            ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A256KW, RSA_OAEP, RSA_OAEP_256, deserialize_compact,
        };

        let keys = self
            .key_repo
            .list_available_asymmetric()
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadRequestFailed).with_source(error)
            })?;

        for key in &keys {
            let KeyData::Asymmetric(data) = &key.data else {
                continue;
            };
            let pem = data.private_key.as_bytes();

            macro_rules! try_decrypt {
                ($alg:expr) => {
                    if let Ok(decrypter) = $alg.decrypter_from_pem(pem) {
                        if let Ok((bytes, _header)) = deserialize_compact(raw, &decrypter) {
                            if let Ok(payload_str) = String::from_utf8(bytes) {
                                return Ok(payload_str);
                            }
                        }
                    }
                };
            }

            try_decrypt!(RSA_OAEP);
            try_decrypt!(RSA_OAEP_256);
            try_decrypt!(ECDH_ES);
            try_decrypt!(ECDH_ES_A128KW);
            try_decrypt!(ECDH_ES_A256KW);
        }

        Err(AppError::from_code(
            AuthorizeErrorCode::RequestObjectEncryptionUnsupported,
        ))
    }

    async fn verify_signed_request_object(
        &self,
        client: &OpenIdConnectClient,
        raw: &str,
        algorithm: &str,
    ) -> Result<jwt::JwtPayload, AppError> {
        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::CredentialLookupFailed).with_source(error)
            })?;

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
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientJsonWebKeySet,
            )
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::CredentialLookupFailed).with_source(error)
            })?;

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

    pub(super) fn merge_request_object_params(
        mut params: AuthorizationRequestParams,
        payload: &serde_json::Value,
    ) -> Result<AuthorizationRequestParams, AppError> {
        if let Some(value) = payload
            .get("response_type")
            .and_then(|value| value.as_str())
        {
            params.response_type = value.to_string();
        }
        if let Some(value) = payload
            .get("response_mode")
            .and_then(|value| value.as_str())
        {
            params.response_mode = Some(value.to_string());
        }
        if let Some(value) = payload.get("client_id").and_then(|value| value.as_str()) {
            params.client_id = value.to_string();
        }
        if let Some(value) = payload.get("redirect_uri").and_then(|value| value.as_str()) {
            params.redirect_uri = value.to_string();
        }
        if let Some(value) = payload.get("scope").and_then(|value| value.as_str()) {
            params.scope = value.to_string();
        }
        if let Some(value) = payload.get("state").and_then(|value| value.as_str()) {
            params.state = value.to_string();
        }
        if let Some(value) = payload.get("nonce").and_then(|value| value.as_str()) {
            params.nonce = Some(value.to_string());
        }
        if let Some(value) = payload.get("login_hint").and_then(|value| value.as_str()) {
            params.login_hint = Some(value.to_string());
        }
        if let Some(value) = payload.get("display").and_then(|value| value.as_str()) {
            params.display = Some(value.to_string());
        }
        if let Some(value) = payload.get("prompt").and_then(|value| value.as_str()) {
            params.prompt = Some(value.to_string());
        }
        if let Some(value) = payload.get("max_age")
            && let Some(value) = value.as_i64()
        {
            params.max_age = Some(value.to_string());
        }
        if let Some(value) = payload.get("ui_locales").and_then(|value| value.as_str()) {
            params.ui_locales = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("claims_locales")
            .and_then(|value| value.as_str())
        {
            params.claims_locales = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("id_token_hint")
            .and_then(|value| value.as_str())
        {
            params.id_token_hint = Some(value.to_string());
        }
        if let Some(value) = payload.get("acr_values").and_then(|value| value.as_str()) {
            params.acr_values = Some(value.to_string());
        }
        if let Some(value) = payload.get("claims") {
            params.claims = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("code_challenge")
            .and_then(|value| value.as_str())
        {
            params.code_challenge = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("code_challenge_method")
            .and_then(|value| value.as_str())
        {
            params.code_challenge_method = Some(value.to_string());
        }

        Ok(params)
    }

    pub(super) fn validate_request_object_claims(
        params: &AuthorizationRequestParams,
        payload: &serde_json::Value,
        issuer: &Url,
    ) -> Result<(), AppError> {
        Self::validate_required_request_object_field(
            payload,
            "response_type",
            params.response_type.as_str(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "response_mode",
            params.response_mode.as_deref(),
        )?;
        Self::validate_required_request_object_field(
            payload,
            "client_id",
            params.client_id.as_str(),
        )?;
        // Per OIDCC-6.1, request object values supersede query parameters.
        // For redirect_uri, we do NOT reject mismatches — the request object's
        // redirect_uri will override the query param during merge.
        // This allows the request object to specify the authoritative redirect_uri.
        Self::validate_required_request_object_field(payload, "scope", params.scope.as_str())?;
        Self::validate_required_request_object_field(payload, "state", params.state.as_str())?;
        Self::validate_optional_request_object_field(payload, "nonce", params.nonce.as_deref())?;
        Self::validate_optional_request_object_field(
            payload,
            "display",
            params.display.as_deref(),
        )?;
        Self::validate_optional_request_object_field(payload, "prompt", params.prompt.as_deref())?;
        Self::validate_optional_numeric_request_object_field(
            payload,
            "max_age",
            params.max_age.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "ui_locales",
            params.ui_locales.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "claims_locales",
            params.claims_locales.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "id_token_hint",
            params.id_token_hint.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "login_hint",
            params.login_hint.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "acr_values",
            params.acr_values.as_deref(),
        )?;
        Self::validate_optional_json_request_object_field(
            payload,
            "claims",
            params.claims.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "code_challenge",
            params.code_challenge.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "code_challenge_method",
            params.code_challenge_method.as_deref(),
        )?;

        if let Some(iss) = payload
            .get(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            && iss != params.client_id
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectIssMismatch,
            ));
        }

        if let Some(aud) = payload.get(JwtClaimNames::AUD) {
            let issuer_value = issuer.as_str();
            let matches = aud
                .as_str()
                .map(|value| value == issuer_value)
                .unwrap_or_else(|| {
                    aud.as_array()
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str())
                                .any(|value| value == issuer_value)
                        })
                        .unwrap_or(false)
                });

            if !matches {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectAudMismatch,
                ));
            }
        }

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = payload
            .get(JwtClaimNames::EXP)
            .and_then(|value| value.as_i64())
            && exp <= now
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectExpired,
            ));
        }

        if let Some(nbf) = payload
            .get(JwtClaimNames::NBF)
            .and_then(|value| value.as_i64())
            && nbf > now
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectNotYetValid,
            ));
        }

        if let Some(iat) = payload
            .get(JwtClaimNames::IAT)
            .and_then(|value| value.as_i64())
            && iat > now
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectIatFuture,
            ));
        }

        Ok(())
    }

    fn validate_required_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: &str,
    ) -> Result<(), AppError> {
        if outer.trim().is_empty() {
            return Ok(());
        }

        if let Some(inner) = payload.get(field).and_then(|value| value.as_str())
            && inner != outer
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                    .with_param("field", field),
            );
        }

        Ok(())
    }

    fn validate_optional_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) =
            (payload.get(field).and_then(|value| value.as_str()), outer)
            && inner != outer
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                    .with_param("field", field),
            );
        }

        Ok(())
    }

    fn validate_optional_numeric_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) =
            (payload.get(field).and_then(|value| value.as_i64()), outer)
            && inner.to_string() != outer
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                    .with_param("field", field),
            );
        }

        Ok(())
    }

    fn validate_optional_json_request_object_field(
        payload: &serde_json::Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) = (payload.get(field), outer) {
            let outer = serde_json::from_str::<serde_json::Value>(outer).map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::RequestObjectJsonInvalid).with_source(error)
            })?;

            if inner != &outer {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", field),
                );
            }
        }

        Ok(())
    }

    pub(super) fn parse_claims_request(raw: &str) -> Result<ClaimsRequest, AppError> {
        let value = serde_json::from_str::<serde_json::Value>(raw).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ClaimsParamInvalid).with_source(error)
        })?;
        let object = value
            .as_object()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClaimsNotObject))?;

        // A `null` value (e.g. from a serialized `Option::None`) is treated as
        // absent. Without this, a claims document produced by serializing
        // `ClaimsRequest` — which emits `"id_token": null` when that section is
        // unset — would be rejected on re-parse as "field not an object".
        let map_field = |field: &str| -> Result<Option<ClaimRequestMap>, AppError> {
            match object.get(field) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(value) => value
                    .as_object()
                    .cloned()
                    .map(ClaimRequestMap::from_json_map)
                    .map(Some)
                    .ok_or_else(|| {
                        AppError::from_code(AuthorizeErrorCode::ClaimsFieldNotObject)
                            .with_param("field", field)
                    }),
            }
        };

        Ok(ClaimsRequest {
            id_token: map_field("id_token")?,
            userinfo: map_field("userinfo")?,
        })
    }

    pub(super) fn extract_request_object_client_id(raw: &str) -> Result<Option<String>, AppError> {
        let payload = Self::decode_request_object_payload_unverified(raw)?;
        Ok(payload
            .get("client_id")
            .and_then(|value| value.as_str())
            .map(str::to_owned))
    }

    fn decode_request_object_payload_unverified(raw: &str) -> Result<serde_json::Value, AppError> {
        let payload_segment = raw
            .split('.')
            .nth(1)
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestObjectEncodingInvalid))?;

        let payload = URL_SAFE_NO_PAD.decode(payload_segment).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestObjectBase64Invalid).with_source(error)
        })?;

        serde_json::from_slice::<serde_json::Value>(&payload).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::RequestObjectPayloadInvalid).with_source(error)
        })
    }
}

#[cfg(test)]
pub(in crate::openid_connect::authorize) fn fetchable_request_uri(request_uri: &Url) -> Url {
    fetchable_url(request_uri)
}

fn map_request_uri_fetch_error(error: RemoteFetchError) -> AppError {
    match error {
        RemoteFetchError::NotHttps => AppError::from_code(AuthorizeErrorCode::RequestUriNotHttps),
        RemoteFetchError::UnsafeHost => {
            AppError::from_code(AuthorizeErrorCode::RequestUriUnsafeHost)
        }
        RemoteFetchError::FetchFailed(error) => {
            AppError::from_code(AuthorizeErrorCode::RequestUriFetchFailed).with_source(error)
        }
        RemoteFetchError::ResolveFailed(error) => {
            AppError::from_code(AuthorizeErrorCode::RequestUriUnsafeHost).with_source(error)
        }
        RemoteFetchError::NotOk => AppError::from_code(AuthorizeErrorCode::RequestUriNot200),
        RemoteFetchError::TooLarge => AppError::from_code(AuthorizeErrorCode::RequestUriTooLarge),
        RemoteFetchError::ReadFailed(error) => {
            AppError::from_code(AuthorizeErrorCode::RequestUriReadFailed).with_source(error)
        }
    }
}

fn decode_request_object_with_jwk(
    raw: &str,
    alg: &str,
    jwk: &identity_domain::key::PublicJwk,
) -> Result<jwt::JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_public_jwk(alg, jwk).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::RequestObjectKeyInvalid)
            .with_param("alg", alg)
            .with_source(error)
    })?;
    decode_with_verifier(raw, verifier.as_ref()).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::RequestObjectVerifyFailed).with_source(error)
    })
}

fn decode_request_object(
    raw: &str,
    alg: &str,
    public_key_pem: &[u8],
) -> Result<jwt::JwtPayload, AppError> {
    let verifier = asymmetric_verifier_from_pem(alg, public_key_pem).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::RequestObjectKeyInvalid)
            .with_param("alg", alg)
            .with_source(error)
    })?;
    decode_with_verifier(raw, verifier.as_ref()).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::RequestObjectVerifyFailed).with_source(error)
    })
}
