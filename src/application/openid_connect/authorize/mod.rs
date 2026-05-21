use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jws::{ES256, ES256K, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512},
    jwt,
};
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        data_protection::DataProtector,
        error::{AppError, codes::authorize::AuthorizeErrorCode},
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    },
    domain::{
        auth::repository::LoginRepository,
        client_authorization::{ClientAuthorizationRepository, ClientAuthorizationType},
        key::{JwaSigningAlgorithm, KeyData, KeyJwkRepository, repository::KeyRepository},
        openid_connect::{
            AuthorizationRequest, AuthorizationRequestData, CodeChallengeMethod, Display,
            OAuthErrorCode, OAuthErrorResponse, OpenIdConnectClient, OpenIdConnectClientRepository,
            OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
            OpenIdConnectCredentialType, PromptValue, ResponseMode, ResponseType, ScopeSet,
            model::authorization_request::ClaimsRequest, model::claim::JwtClaimNames,
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

impl AuthorizeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
        login_repo: Arc<dyn LoginRepository>,
        user_repo: Arc<dyn UserRepository>,
        key_repo: Arc<dyn KeyRepository>,
        key_jwk_repo: Arc<dyn KeyJwkRepository>,
        provider_service: Arc<OpenIdProviderService>,
        signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            client_repo,
            credential_repo,
            client_authorization_repo,
            login_repo,
            user_repo,
            key_repo,
            key_jwk_repo,
            provider_service,
            signing_algorithm_detector,
            http_client: request_uri_http_client()
                .build()
                .expect("request_uri HTTP client must build"),
            data_protector,
        }
    }
}

fn request_uri_http_client() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5));

    #[cfg(feature = "oidc-conformance")]
    {
        builder.danger_accept_invalid_certs(true)
    }

    #[cfg(not(feature = "oidc-conformance"))]
    {
        builder
    }
}

mod flow;
mod implicit_flow;
mod interaction;
mod protection;
mod request_object;
mod signing;
mod validation;

pub use interaction::{
    ContinueAction, determine_continue_action, selected_session_exceeds_max_age,
    stored_request_has_prompt,
};

#[cfg(test)]
mod tests;
