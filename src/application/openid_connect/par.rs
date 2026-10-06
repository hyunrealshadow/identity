use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use identity_domain::{
    client_authorization::{
        ClientAuthorizationData, ClientAuthorizationRepository, PushedAuthorizationRequestData,
    },
    openid_connect::{ClientAssertionType, par::PAR_REQUEST_URI_PREFIX},
};
use rand::{RngExt, rng};
use sha2::{Digest, Sha256};

use crate::{
    error::{
        AppError,
        codes::{common::CommonErrorCode, token::TokenErrorCode},
    },
    openid_connect::{
        authorize::{AuthorizationRequestParams, AuthorizeService},
        client_authentication::ClientAuthenticator,
        provider::OpenIdProviderService,
        token::resolve_client_id,
    },
};

pub fn request_uri_digest(uri: &str) -> String {
    Sha256::digest(uri.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub struct PushedAuthorizationParams {
    pub authorization: AuthorizationRequestParams,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<ClientAssertionType>,
    pub client_assertion: Option<String>,
}
#[derive(Debug, serde::Serialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

pub struct PushedAuthorizationService {
    client_authentication: Arc<ClientAuthenticator>,
    authorize: AuthorizeService,
    repository: Arc<dyn ClientAuthorizationRepository>,
    provider: Arc<OpenIdProviderService>,
}
impl PushedAuthorizationService {
    pub fn new(
        client_authentication: Arc<ClientAuthenticator>,
        authorize: AuthorizeService,
        repository: Arc<dyn ClientAuthorizationRepository>,
        provider: Arc<OpenIdProviderService>,
    ) -> Self {
        Self {
            client_authentication,
            authorize,
            repository,
            provider,
        }
    }
    pub async fn push(
        &self,
        mut params: PushedAuthorizationParams,
    ) -> Result<PushedAuthorizationResponse, AppError> {
        if params.authorization.request.is_none() && params.authorization.client_id.is_empty() {
            return Err(AppError::from_code(TokenErrorCode::ClientIdRequired));
        }
        if params.authorization.request.is_none() && params.authorization.client_id.is_empty() {
            return Err(AppError::from_code(TokenErrorCode::ClientIdRequired));
        }
        if params.authorization.client_id.is_empty()
            && params.client_assertion.is_none()
            && let Some(request) = params.authorization.request.as_deref()
            && let Some(client_id) = AuthorizeService::extract_request_object_client_id(request)?
        {
            params.authorization.client_id = client_id;
        }
        params.authorization.client_id = resolve_client_id(
            (!params.authorization.client_id.is_empty())
                .then(|| params.authorization.client_id.clone()),
            params.client_assertion_type,
            params.client_assertion.as_deref(),
        )?;
        let client_id = &params.authorization.client_id;
        if client_id.is_empty() {
            return Err(AppError::from_code(TokenErrorCode::ClientIdRequired));
        }
        let client_oid = self
            .client_authentication
            .authenticate_client_for_par(
                client_id,
                params.client_secret.as_deref(),
                params.client_secret_basic,
                params.client_assertion_type,
                params.client_assertion.as_deref(),
            )
            .await?;
        if params.authorization.request_uri.is_some() {
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }
        let (_, client) = self
            .authorize
            .validate_pushed_request(params.authorization.clone())
            .await?;
        if client.client().oid != client_oid {
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }
        let expires_in = self
            .provider
            .pushed_authorization_settings()
            .request_ttl_seconds;
        let random: [u8; 32] = rng().random();
        let request_uri = format!("{PAR_REQUEST_URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(random));
        self.repository
            .create(
                client_oid,
                ClientAuthorizationData::PushedAuthorizationRequest(
                    PushedAuthorizationRequestData {
                        request_uri_digest: request_uri_digest(&request_uri),
                        parameters: params.authorization,
                    },
                ),
                Utc::now() + Duration::seconds(expires_in),
            )
            .await
            .map_err(AppError::map_source(
                CommonErrorCode::PushedRequestStorageFailed,
            ))?;
        Ok(PushedAuthorizationResponse {
            request_uri,
            expires_in,
        })
    }
}
