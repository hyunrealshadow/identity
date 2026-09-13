//! OAuth client authentication shared by the endpoints that accept client
//! credentials (the token endpoint and the device authorization endpoint).
//!
//! The rules are the ones the token endpoint always applied: the registered
//! `token_endpoint_auth_method` decides how a confidential client proves
//! itself, and clients registered as public clients authenticate with a
//! `client_id` only. Keeping one implementation means a flow cannot
//! accidentally accept a weaker method than the registration allows.

use std::sync::Arc;
use std::time::Duration;

use josekit::jwt;
use josekit::jwt::JwtPayload;
use uuid::Uuid;

use crate::application::error::{AppError, codes::token::TokenErrorCode};
use crate::domain::key::JwsAlgorithm;
use crate::domain::openid_connect::model::claim::JwtClaimNames;
use crate::domain::openid_connect::{
    OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectCredentialData,
    OpenIdConnectCredentialRepository, OpenIdConnectCredentialType, TokenEndpointAuthMethod,
};
use crate::openid_connect::jwt_checks::{
    JwtTimeValidationError, audience_matches, validate_required_exp_and_optional_window,
};
use crate::openid_connect::provider::OpenIdProviderService;
use crate::openid_connect::remote::{
    DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
    fetch_https_public_document, remote_http_client,
};
use crate::openid_connect::token::helpers::{
    decode_assertion_with_alg, decode_assertion_with_hmac_alg, decode_assertion_with_jwk,
};

pub struct ClientAuthenticator {
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    provider_service: Arc<OpenIdProviderService>,
}

pub struct ClientAuthenticatorDependencies {
    pub client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    pub provider_service: Arc<OpenIdProviderService>,
}

impl ClientAuthenticator {
    #[must_use]
    pub fn new(deps: ClientAuthenticatorDependencies) -> Self {
        Self {
            client_repo: deps.client_repo,
            credential_repo: deps.credential_repo,
            provider_service: deps.provider_service,
        }
    }

    async fn load_client(&self, client_id: &str) -> Result<OpenIdConnectClient, AppError> {
        let client_oid = Uuid::parse_str(client_id).map_err(|error| {
            AppError::from_code(TokenErrorCode::ClientIdInvalid).with_source(error)
        })?;

        self.client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(TokenErrorCode::ClientNotFound))
    }

    pub async fn authenticate_client_secret_basic(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Uuid, AppError> {
        self.authenticate_client_secret(client_id, client_secret)
            .await
    }

    pub async fn authenticate_client_secret_post(
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
            .find_active_by_client_oid_and_type(
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

    pub async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        if let (
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(assertion),
        ) = (client_assertion_type, client_assertion)
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

            return match client.metadata().token_endpoint_auth_method {
                Some(identity_domain::openid_connect::TokenEndpointAuthMethod::ClientSecretJwt) => {
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

        if client.metadata().token_endpoint_auth_method
            == Some(identity_domain::openid_connect::TokenEndpointAuthMethod::ClientSecretBasic)
        {
            self.authenticate_client_secret_basic(client_id, client_secret)
                .await
        } else {
            self.authenticate_client_secret_post(client_id, client_secret)
                .await
        }
    }

    /// Authenticates a client for a flow public clients may use and returns
    /// the loaded client.
    ///
    /// A client registered with `token_endpoint_auth_method: none` proves
    /// itself with its `client_id` only; every other client must present its
    /// secret or assertion. The registered method decides, so the check cannot
    /// be bypassed by omitting credentials.
    pub async fn authenticate_client_request(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
        client_assertion: Option<&str>,
    ) -> Result<OpenIdConnectClient, AppError> {
        if client_secret.is_none() && client_assertion.is_none() {
            let client = self.load_client(client_id).await?;
            if client.metadata().token_endpoint_auth_method == Some(TokenEndpointAuthMethod::None) {
                return Ok(client);
            }

            return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        }

        let client = self.load_client(client_id).await?;
        self.authenticate_client(
            client_id,
            client_secret,
            client_assertion_type,
            client_assertion,
        )
        .await?;

        Ok(client)
    }

    pub async fn authenticate_private_key_jwt(
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

    pub async fn authenticate_client_secret_jwt(
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

    pub async fn verify_client_assertion(
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
            .unwrap_or("none")
            .parse::<JwsAlgorithm>()
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::AssertionAlgUnsupported).with_source(error)
            })?;
        if algorithm == JwsAlgorithm::None && !cfg!(feature = "allow-none-alg") {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }
        if let Some(registered_algorithm) = client.metadata().token_endpoint_auth_signing_alg
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }

        let credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
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
            .find_active_by_client_oid_and_type(
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

    pub async fn verify_client_secret_assertion(
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
            .unwrap_or("none")
            .parse::<JwsAlgorithm>()
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::AssertionAlgUnsupported).with_source(error)
            })?;
        if algorithm == JwsAlgorithm::None && !cfg!(feature = "allow-none-alg") {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }
        if let Some(registered_algorithm) = client.metadata().token_endpoint_auth_signing_alg
            && registered_algorithm != algorithm
        {
            return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
        }

        let credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
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
    algorithm: JwsAlgorithm,
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
    if !cfg!(feature = "allow-none-alg")
        && jwks.keys.iter().any(|jwk| jwk.algorithm() == Some("none"))
    {
        return Err(AppError::from_code(TokenErrorCode::AssertionVerifyFailed));
    }
    for jwk in jwks.keys {
        if let Ok(payload) = decode_assertion_with_jwk(algorithm, assertion, &jwk) {
            return Ok(Some(payload));
        }
    }

    Ok(None)
}
