use super::*;
use crate::openid_connect::jwt_checks::{
    JwtTimeValidationError, audience_matches, validate_required_exp_and_optional_window,
};
use crate::openid_connect::remote::{
    DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
    fetch_https_public_document, remote_http_client,
};
use std::time::Duration;

impl TokenService {
    pub(super) async fn authenticate_client_secret_basic(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        self.authenticate_client_secret(client_id, client_secret)
            .await
    }

    pub(super) async fn authenticate_client_secret_post(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        self.authenticate_client_secret(client_id, client_secret)
            .await
    }

    async fn authenticate_client_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        let valid = credentials.into_iter().any(|credential| {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = &credential.data {
                subtle::ConstantTimeEq::ct_eq(secret.as_bytes(), client_secret.as_bytes()).into()
            } else {
                false
            }
        });

        if !valid {
            return Err(AppError::from_code(
                TokenErrorCode::ClientCredentialsInvalid,
            ));
        }

        Ok(client.client().oid)
    }

    pub(super) async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion_type: Option<&str>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        if let (Some(assertion_type), Some(assertion)) = (client_assertion_type, client_assertion)
            && assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        {
            let client_oid = Uuid::parse_str(client_id).map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
            })?;
            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

            return match client.metadata().token_endpoint_auth_method.as_deref() {
                Some("client_secret_jwt") => {
                    self.authenticate_client_secret_jwt(client_id, assertion)
                        .await
                }
                _ => {
                    self.authenticate_private_key_jwt(client_id, assertion)
                        .await
                }
            };
        }

        let Some(client_secret) = client_secret else {
            let client_oid = Uuid::parse_str(client_id).map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
            })?;
            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(|error| {
                    AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
                })?
                .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

            if client.metadata().settings.allow_public_client_flow {
                return Ok(client.client().oid);
            }

            return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        };

        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        if client.metadata().token_endpoint_auth_method.as_deref() == Some("client_secret_basic") {
            self.authenticate_client_secret_basic(client_id, client_secret)
                .await
        } else {
            self.authenticate_client_secret_post(client_id, client_secret)
                .await
        }
    }

    pub(super) async fn authenticate_private_key_jwt(
        &self,
        client_id: &str,
        assertion: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let payload = self.verify_client_assertion(&client, assertion).await?;
        self.validate_client_assertion_payload(client_id, &payload)?;

        Ok(client.client().oid)
    }

    pub(super) async fn authenticate_client_secret_jwt(
        &self,
        client_id: &str,
        assertion: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))?;

        let payload = self
            .verify_client_secret_assertion(&client, assertion)
            .await?;
        self.validate_client_assertion_payload(client_id, &payload)?;

        Ok(client.client().oid)
    }

    fn validate_client_assertion_payload(
        &self,
        client_id: &str,
        payload: &JwtPayload,
    ) -> Result<(), AppError> {
        let issuer = self.provider_service.issuer()?;

        let iss = payload
            .claim(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionIssMissing))?;
        let sub = payload
            .subject()
            .ok_or_else(|| AppError::from_code(TokenErrorCode::AssertionSubMissing))?;
        if iss != client_id || sub != client_id {
            return Err(AppError::from_code(TokenErrorCode::AssertionIssSubMismatch));
        }

        let issuer_base = issuer.as_str().trim_end_matches('/');
        let token_endpoint = format!("{issuer_base}/oauth2/token");
        let valid_audiences = [issuer.as_str(), issuer_base, token_endpoint.as_str()];
        if !audience_matches(payload, &valid_audiences) {
            return Err(AppError::from_code(TokenErrorCode::AssertionAudMismatch));
        }

        let now = chrono::Utc::now().timestamp();
        validate_required_exp_and_optional_window(payload, now).map_err(|error| match error {
            JwtTimeValidationError::ExpMissing | JwtTimeValidationError::Expired => {
                AppError::from_code(TokenErrorCode::AssertionExpired)
            }
            JwtTimeValidationError::NotYetValid | JwtTimeValidationError::IssuedInFuture => {
                AppError::from_code(TokenErrorCode::AssertionNotYetValid)
            }
        })?;

        Ok(())
    }

    pub(super) async fn verify_client_assertion(
        &self,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion).map_err(|error| {
            AppError::from_code(TokenErrorCode::AssertionHeaderInvalid).with_source(error)
        })?;
        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        if let Some(registered_algorithm) =
            client.metadata().token_endpoint_auth_signing_alg.as_deref()
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientPublicKey { public_key, jwk } =
                credential.data
            {
                if let Some(jwk) = jwk
                    && let Ok(payload) = decode_assertion_with_jwk(algorithm, assertion, &jwk)
                {
                    return Ok(payload);
                }
                if let Ok(payload) =
                    decode_assertion_with_alg(algorithm, assertion, public_key.as_bytes())
                {
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
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;
        for credential in jwks_credentials {
            if let OpenIdConnectCredentialData::ClientJsonWebKeySet {
                public_keys,
                jwks,
                jwks_uri,
                ..
            } = credential.data
            {
                for jwk in jwks {
                    if let Ok(payload) = decode_assertion_with_jwk(algorithm, assertion, &jwk) {
                        return Ok(payload);
                    }
                }
                for public_key in public_keys {
                    if let Ok(payload) =
                        decode_assertion_with_alg(algorithm, assertion, public_key.as_bytes())
                    {
                        return Ok(payload);
                    }
                }
                if let Some(payload) =
                    fetch_and_verify_jwks_uri(&jwks_uri, algorithm, assertion).await?
                {
                    return Ok(payload);
                }
            }
        }

        Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed))
    }

    pub(super) async fn verify_client_secret_assertion(
        &self,
        client: &identity_domain::openid_connect::OpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion).map_err(|error| {
            AppError::from_code(TokenErrorCode::AssertionHeaderInvalid).with_source(error)
        })?;
        let algorithm = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        if let Some(registered_algorithm) =
            client.metadata().token_endpoint_auth_signing_alg.as_deref()
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }

        let credentials = self
            .credential_repo
            .find_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::CredentialLookupFailed).with_source(error)
            })?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = credential.data
                && let Ok(payload) =
                    decode_assertion_with_hmac_alg(algorithm, assertion, secret.as_bytes())
            {
                return Ok(payload);
            }
        }

        Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed))
    }
}

#[derive(Debug, serde::Deserialize)]
struct RemoteJwks {
    keys: Vec<identity_domain::key::PublicJwk>,
}

async fn fetch_and_verify_jwks_uri(
    jwks_uri: &url::Url,
    algorithm: &str,
    assertion: &str,
) -> Result<Option<JwtPayload>, AppError> {
    let client = remote_http_client(RemoteFetchPolicy::new(
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        Duration::from_secs(5),
        conformance_allows_invalid_certs(),
    ))
    .map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })?;
    let body =
        match fetch_https_public_document(&client, jwks_uri, DEFAULT_REMOTE_DOCUMENT_MAX_BYTES)
            .await
        {
            Ok(body) => body,
            Err(crate::openid_connect::remote::RemoteFetchError::NotOk) => return Ok(None),
            Err(error) => {
                return Err(
                    AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
                );
            }
        };

    let jwks = serde_json::from_slice::<RemoteJwks>(&body).map_err(|error| {
        AppError::from_code(TokenErrorCode::AssertionVerifyFailed).with_source(error)
    })?;
    for jwk in jwks.keys {
        if let Ok(payload) = decode_assertion_with_jwk(algorithm, assertion, &jwk) {
            return Ok(Some(payload));
        }
    }

    Ok(None)
}
