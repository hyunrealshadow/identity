//! OAuth client authentication shared by the endpoints that accept client
//! credentials (the token endpoint and the device authorization endpoint).
//!
//! The rules are the ones the token endpoint always applied: the registered
//! `token_endpoint_auth_methods` decide how a confidential client proves
//! itself, and clients enabling `allow_public_client_flow` and registering
//! `none` authenticate with a `client_id` only. Keeping one implementation
//! means a flow cannot accidentally accept a weaker method than the registration allows.

use std::sync::Arc;

use chrono::Utc;
use identity_domain::{
    key::PublicJwk,
    openid_connect::{
        ClientAssertionType, OpenIdConnectClient as OpenidConnectOpenIdConnectClient,
    },
};
use josekit::{jwt, jwt::JwtPayload};
use serde_json::from_slice;
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

use crate::{
    application::error::{
        AppError,
        codes::token::{self, TokenErrorCode},
    },
    domain::{
        key::JwsAlgorithm,
        openid_connect::{
            OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectCredentialData,
            OpenIdConnectCredentialRepository, OpenIdConnectCredentialType,
            TokenEndpointAuthMethod, model::claim::JwtClaimNames,
        },
    },
    openid_connect::{
        jwt_checks::{
            JwtTimeValidationError, audience_matches, validate_required_exp_and_optional_window,
        },
        provider::OpenIdProviderService,
        remote::{
            DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteDocumentFetcher, RemoteFetchError,
            UnconfiguredRemoteDocumentFetcher,
        },
        token::helpers::{
            decode_assertion_with_alg, decode_assertion_with_hmac_alg, decode_assertion_with_jwk,
        },
    },
};

#[derive(Clone)]
pub struct ClientAuthenticator {
    par_endpoint: bool,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    provider_service: Arc<OpenIdProviderService>,
    remote_fetcher: Arc<dyn RemoteDocumentFetcher>,
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
            par_endpoint: false,
            client_repo: deps.client_repo,
            credential_repo: deps.credential_repo,
            provider_service: deps.provider_service,
            remote_fetcher: Arc::new(UnconfiguredRemoteDocumentFetcher),
        }
    }

    #[must_use]
    pub fn with_remote_fetcher(mut self, remote_fetcher: Arc<dyn RemoteDocumentFetcher>) -> Self {
        self.remote_fetcher = remote_fetcher;
        self
    }

    pub async fn authenticate_client_for_par(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_secret_basic: bool,
        client_assertion_type: Option<ClientAssertionType>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        let mut authenticator = self.clone();
        authenticator.par_endpoint = true;
        authenticator
            .authenticate_client_request(
                client_id,
                client_secret,
                client_secret_basic,
                client_assertion_type,
                client_assertion,
            )
            .await
            .map(|client| client.client().oid)
    }

    async fn load_client(&self, client_id: &str) -> Result<OpenIdConnectClient, AppError> {
        let client_oid = identity_domain::openid_connect::identifier::parse_client_id(client_id)
            .map_err(token::error::ClientIdInvalid::map_source())?;

        self.client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(token::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| token::error::ClientNotFound.into_error())
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
        let client_oid = identity_domain::openid_connect::identifier::parse_client_id(client_id)
            .map_err(token::error::ClientIdInvalid::map_source())?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(token::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| token::error::ClientNotFound.into_error())?;

        let credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(token::error::CredentialLookupFailed::map_source())?;

        let valid = credentials.into_iter().any(|credential| {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = &credential.data {
                ConstantTimeEq::ct_eq(secret.as_bytes(), client_secret.as_bytes()).into()
            } else {
                false
            }
        });

        if !valid {
            return Err(token::error::ClientCredentialsInvalid.into_error());
        }

        Ok(client.client().oid)
    }

    pub async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_secret_basic: bool,
        client_assertion_type: Option<ClientAssertionType>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        let result = self
            .authenticate_client_credentials(
                client_id,
                client_secret,
                client_secret_basic,
                client_assertion_type,
                client_assertion,
            )
            .await;
        if let Err(error) = &result
            && rejects_presented_credential(error)
            && let Ok(client_oid) =
                identity_domain::openid_connect::identifier::parse_client_id(client_id)
        {
            // A rejected credential can only be reached for an existing client.
            self.credential_repo
                .record_authentication_failure(client_oid)
                .await
                .map_err(token::error::CredentialLookupFailed::map_source())?;
        }
        result
    }

    async fn authenticate_client_credentials(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_secret_basic: bool,
        client_assertion_type: Option<ClientAssertionType>,
        client_assertion: Option<&str>,
    ) -> Result<Uuid, AppError> {
        if client_assertion_type.is_some() != client_assertion.is_some()
            || (client_secret.is_some() && client_assertion.is_some())
        {
            return Err(token::error::ClientAuthRequired.into_error());
        }
        if let (Some(ClientAssertionType::JwtBearer), Some(assertion)) =
            (client_assertion_type, client_assertion)
        {
            let client_oid =
                identity_domain::openid_connect::identifier::parse_client_id(client_id)
                    .map_err(token::error::ClientIdInvalid::map_source())?;
            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(token::error::ClientLookupFailed::map_source())?
                .ok_or_else(|| token::error::ClientNotFound.into_error())?;

            let header = jwt::decode_header(assertion)
                .map_err(token::error::AssertionHeaderInvalid::map_source())?;
            let alg_str = header
                .claim(JwtClaimNames::ALG)
                .and_then(|value| value.as_str())
                .unwrap_or("none");
            let algorithm = alg_str.parse::<JwsAlgorithm>().map_err(|error| {
                token::error::AssertionAlgUnsupported::new(alg_str).with_source(error)
            })?;
            let method = match algorithm {
                JwsAlgorithm::Hs256 | JwsAlgorithm::Hs384 | JwsAlgorithm::Hs512 => {
                    TokenEndpointAuthMethod::ClientSecretJwt
                }
                JwsAlgorithm::Asymmetric(_) => TokenEndpointAuthMethod::PrivateKeyJwt,
                JwsAlgorithm::None => {
                    return Err(token::error::AssertionVerifyFailed.into_error());
                }
            };
            if !client.metadata().allows_token_endpoint_auth_method(method) {
                return Err(token::error::ClientAuthRequired.into_error());
            }
            return match method {
                TokenEndpointAuthMethod::ClientSecretJwt => {
                    self.authenticate_client_secret_jwt(client_id, assertion)
                        .await
                }
                TokenEndpointAuthMethod::PrivateKeyJwt => {
                    self.authenticate_private_key_jwt(client_id, assertion)
                        .await
                }
                _ => Err(token::error::ClientAuthRequired.into_error()),
            };
        }

        let Some(client_secret) = client_secret else {
            let client_oid =
                identity_domain::openid_connect::identifier::parse_client_id(client_id)
                    .map_err(token::error::ClientIdInvalid::map_source())?;
            let client = self
                .client_repo
                .find_by_oid(client_oid)
                .await
                .map_err(token::error::ClientLookupFailed::map_source())?
                .ok_or_else(|| token::error::ClientNotFound.into_error())?;

            if client
                .metadata()
                .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::None)
            {
                return Ok(client.client().oid);
            }

            return Err(token::error::ClientAuthRequired.into_error());
        };

        let client_oid = identity_domain::openid_connect::identifier::parse_client_id(client_id)
            .map_err(token::error::ClientIdInvalid::map_source())?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(token::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| token::error::ClientNotFound.into_error())?;

        if client_secret_basic
            && client
                .metadata()
                .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::ClientSecretBasic)
        {
            self.authenticate_client_secret_basic(client_id, client_secret)
                .await
        } else if !client_secret_basic
            && client
                .metadata()
                .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::ClientSecretPost)
        {
            self.authenticate_client_secret_post(client_id, client_secret)
                .await
        } else {
            Err(token::error::ClientAuthRequired.into_error())
        }
    }

    /// Authenticates a client for a flow public clients may use and returns
    /// the loaded client.
    ///
    /// A client enabling `allow_public_client_flow` and registering `none`
    /// proves itself with its `client_id` only; every other client must present
    /// its secret or assertion. The registered method decides, so the check cannot
    /// be bypassed by omitting credentials.
    pub async fn authenticate_client_request(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        client_secret_basic: bool,
        client_assertion_type: Option<ClientAssertionType>,
        client_assertion: Option<&str>,
    ) -> Result<OpenIdConnectClient, AppError> {
        if client_secret.is_none() && client_assertion.is_none() {
            let client = self.load_client(client_id).await?;
            if client
                .metadata()
                .allows_token_endpoint_auth_method(TokenEndpointAuthMethod::None)
            {
                return Ok(client);
            }

            return Err(token::error::ClientAuthRequired.into_error());
        }

        let client = self.load_client(client_id).await?;
        self.authenticate_client(
            client_id,
            client_secret,
            client_secret_basic,
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
        let client_oid = identity_domain::openid_connect::identifier::parse_client_id(client_id)
            .map_err(token::error::ClientIdInvalid::map_source())?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(token::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| token::error::ClientNotFound.into_error())?;

        let payload = self.verify_client_assertion(&client, assertion).await?;
        self.validate_client_assertion_payload(client_id, &payload)?;

        Ok(client.client().oid)
    }

    pub async fn authenticate_client_secret_jwt(
        &self,
        client_id: &str,
        assertion: &str,
    ) -> Result<Uuid, AppError> {
        let client_oid = identity_domain::openid_connect::identifier::parse_client_id(client_id)
            .map_err(token::error::ClientIdInvalid::map_source())?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(token::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| token::error::ClientNotFound.into_error())?;

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
            .ok_or_else(|| token::error::AssertionIssMissing.into_error())?;
        let sub = payload
            .subject()
            .ok_or_else(|| token::error::AssertionSubMissing.into_error())?;
        if iss != client_id || sub != client_id {
            return Err(token::error::AssertionIssSubMismatch.into_error());
        }

        let issuer_base = issuer.as_str().trim_end_matches('/');
        let token_endpoint = format!("{issuer_base}/oauth2/token");
        let revocation_endpoint = format!("{issuer_base}/oauth2/revoke");
        let introspection_endpoint = format!("{issuer_base}/oauth2/introspect");
        let par_endpoint = format!("{issuer_base}/oauth2/par");
        let mut valid_audiences = vec![
            issuer.as_str(),
            issuer_base,
            token_endpoint.as_str(),
            revocation_endpoint.as_str(),
            introspection_endpoint.as_str(),
        ];
        if self.par_endpoint {
            valid_audiences.push(par_endpoint.as_str());
        }
        if !audience_matches(payload, &valid_audiences) {
            return Err(token::error::AssertionAudMismatch.into_error());
        }

        let now = Utc::now().timestamp();
        validate_required_exp_and_optional_window(payload, now).map_err(|error| match error {
            JwtTimeValidationError::ExpMissing | JwtTimeValidationError::Expired => {
                token::error::AssertionExpired.into_error()
            }
            JwtTimeValidationError::NotYetValid | JwtTimeValidationError::IssuedInFuture => {
                token::error::AssertionNotYetValid.into_error()
            }
        })?;

        Ok(())
    }

    pub async fn verify_client_assertion(
        &self,
        client: &OpenidConnectOpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion)
            .map_err(token::error::AssertionHeaderInvalid::map_source())?;
        let alg_str = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        let algorithm = alg_str.parse::<JwsAlgorithm>().map_err(|error| {
            token::error::AssertionAlgUnsupported::new(alg_str).with_source(error)
        })?;
        if algorithm == JwsAlgorithm::None && !cfg!(feature = "allow-none-alg") {
            return Err(token::error::AssertionVerifyFailed.into_error());
        }
        if let Some(registered_algorithms) = &client.metadata().token_endpoint_auth_signing_algs
            && !registered_algorithms.contains(&algorithm)
        {
            return Err(token::error::AssertionVerifyFailed.into_error());
        }

        let credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientPublicKey,
            )
            .await
            .map_err(token::error::CredentialLookupFailed::map_source())?;

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
            .map_err(token::error::CredentialLookupFailed::map_source())?;
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
                if let Some(payload) = fetch_and_verify_jwks_uri(
                    self.remote_fetcher.as_ref(),
                    &jwks_uri,
                    algorithm,
                    assertion,
                )
                .await?
                {
                    return Ok(payload);
                }
            }
        }

        Err(token::error::AssertionVerifyFailed.into_error())
    }

    pub async fn verify_client_secret_assertion(
        &self,
        client: &OpenidConnectOpenIdConnectClient,
        assertion: &str,
    ) -> Result<JwtPayload, AppError> {
        let header = jwt::decode_header(assertion)
            .map_err(token::error::AssertionHeaderInvalid::map_source())?;
        let alg_str = header
            .claim(JwtClaimNames::ALG)
            .and_then(|value| value.as_str())
            .unwrap_or("none");
        let algorithm = alg_str.parse::<JwsAlgorithm>().map_err(|error| {
            token::error::AssertionAlgUnsupported::new(alg_str).with_source(error)
        })?;
        if algorithm == JwsAlgorithm::None && !cfg!(feature = "allow-none-alg") {
            return Err(token::error::AssertionVerifyFailed.into_error());
        }
        if let Some(registered_algorithms) = &client.metadata().token_endpoint_auth_signing_algs
            && !registered_algorithms.contains(&algorithm)
        {
            return Err(token::error::AssertionVerifyFailed.into_error());
        }

        let credentials = self
            .credential_repo
            .find_active_by_client_oid_and_type(
                client.client().oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(token::error::CredentialLookupFailed::map_source())?;

        for credential in credentials {
            if let OpenIdConnectCredentialData::ClientSecret { secret } = credential.data
                && let Ok(payload) =
                    decode_assertion_with_hmac_alg(algorithm, assertion, secret.as_bytes())
            {
                return Ok(payload);
            }
        }

        Err(token::error::AssertionVerifyFailed.into_error())
    }
}

#[derive(Debug, serde::Deserialize)]
struct RemoteJwks {
    keys: Vec<PublicJwk>,
}

async fn fetch_and_verify_jwks_uri(
    remote_fetcher: &dyn RemoteDocumentFetcher,
    jwks_uri: &Url,
    algorithm: JwsAlgorithm,
    assertion: &str,
) -> Result<Option<JwtPayload>, AppError> {
    let body = match remote_fetcher
        .fetch_https_public_document(jwks_uri, DEFAULT_REMOTE_DOCUMENT_MAX_BYTES)
        .await
    {
        Ok(body) => body,
        Err(RemoteFetchError::NotOk) => return Ok(None),
        Err(error) => {
            return Err(token::error::AssertionVerifyFailed.with_source(error));
        }
    };

    let jwks = from_slice::<RemoteJwks>(&body)
        .map_err(token::error::AssertionVerifyFailed::map_source())?;
    if !cfg!(feature = "allow-none-alg")
        && jwks.keys.iter().any(|jwk| jwk.algorithm() == Some("none"))
    {
        return Err(token::error::AssertionVerifyFailed.into_error());
    }
    for jwk in jwks.keys {
        if let Ok(payload) = decode_assertion_with_jwk(algorithm, assertion, &jwk) {
            return Ok(Some(payload));
        }
    }

    Ok(None)
}

/// Whether authentication failed because the client's presented secret or
/// assertion was rejected, rather than a malformed or unsupported request.
fn rejects_presented_credential(error: &AppError) -> bool {
    [
        TokenErrorCode::ClientCredentialsInvalid,
        TokenErrorCode::AssertionIssMissing,
        TokenErrorCode::AssertionSubMissing,
        TokenErrorCode::AssertionIssSubMismatch,
        TokenErrorCode::AssertionAudMismatch,
        TokenErrorCode::AssertionExpired,
        TokenErrorCode::AssertionNotYetValid,
        TokenErrorCode::AssertionVerifyFailed,
    ]
    .into_iter()
    .any(|code| error.is(code))
}
