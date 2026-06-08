use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::jwt;
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        data_protection::DataProtector,
        error::{AppError, codes::authorize::AuthorizeErrorCode},
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
        openid_connect::remote::{
            DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
            remote_http_client,
        },
    },
    domain::{
        auth::repository::LoginRepository,
        client_authorization::{ClientAuthorizationRepository, ClientAuthorizationType},
        key::{JwaSigningAlgorithm, KeyData, KeyJwkRepository, repository::KeyRepository},
        openid_connect::{
            AuthorizationRequest, AuthorizationRequestData, ClaimRequestMap, CodeChallengeMethod,
            Display, OAuthErrorCode, OAuthErrorResponse, OpenIdConnectClient,
            OpenIdConnectClientRepository, OpenIdConnectCredentialData,
            OpenIdConnectCredentialRepository, OpenIdConnectCredentialType, PromptValue,
            ResponseMode, ResponseType, ScopeSet, model::authorization_request::ClaimsRequest,
            model::claim::JwtClaimNames,
        },
        user::{UserOid, repository::UserRepository},
    },
};

#[derive(Debug, Clone)]
pub struct AuthorizationRequestParams {
    pub response_type: String,
    pub response_mode: Option<String>,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub display: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub struct AuthorizeService {
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    login_repo: Arc<dyn LoginRepository>,
    user_repo: Arc<dyn UserRepository>,
    key_repo: Arc<dyn KeyRepository>,
    key_jwk_repo: Arc<dyn KeyJwkRepository>,
    provider_service: Arc<OpenIdProviderService>,
    signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    http_client: reqwest::Client,
    data_protector: Arc<dyn DataProtector>,
}

pub struct AuthorizeServiceDependencies {
    pub client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    pub client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    pub login_repo: Arc<dyn LoginRepository>,
    pub user_repo: Arc<dyn UserRepository>,
    pub key_repo: Arc<dyn KeyRepository>,
    pub key_jwk_repo: Arc<dyn KeyJwkRepository>,
    pub provider_service: Arc<OpenIdProviderService>,
    pub signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    pub data_protector: Arc<dyn DataProtector>,
}

impl AuthorizeService {
    pub fn new(deps: AuthorizeServiceDependencies) -> Self {
        Self {
            client_repo: deps.client_repo,
            credential_repo: deps.credential_repo,
            client_authorization_repo: deps.client_authorization_repo,
            login_repo: deps.login_repo,
            user_repo: deps.user_repo,
            key_repo: deps.key_repo,
            key_jwk_repo: deps.key_jwk_repo,
            provider_service: deps.provider_service,
            signing_algorithm_detector: deps.signing_algorithm_detector,
            http_client: request_uri_http_client().expect("request_uri HTTP client must build"),
            data_protector: deps.data_protector,
        }
    }
}

fn request_uri_http_client() -> Result<reqwest::Client, reqwest::Error> {
    remote_http_client(RemoteFetchPolicy::new(
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        Duration::from_secs(5),
        conformance_allows_invalid_certs(),
    ))
}

mod flow;
mod implicit_flow;
mod interaction;
mod protection;
mod request_object;
mod signing;
mod third_party_initiated;
mod validation;

pub use interaction::{
    ContinueAction, determine_continue_action, selected_session_exceeds_max_age,
    stored_request_has_prompt,
};
pub use third_party_initiated::ThirdPartyInitiatedLoginRequest;

#[cfg(test)]
mod tests;
