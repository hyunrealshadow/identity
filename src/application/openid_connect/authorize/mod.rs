use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{jws::RS256, jwt};
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        data_protection::DataProtector,
        error::{AppError, codes::authorize::AuthorizeErrorCode},
        openid_connect::provider::OpenIdProviderService,
    },
    domain::{
        auth::repository::LoginRepository,
        client_request::{ClientRequestRepository, ClientRequestType},
        openid_connect::{
            AuthorizationRequest, AuthorizationRequestData, CodeChallengeMethod, Display,
            OAuthErrorCode, OAuthErrorResponse, OpenIdConnectClient, OpenIdConnectClientRepository,
            OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
            OpenIdConnectCredentialType, PromptValue, ResponseType, ScopeSet,
            model::authorization_request::ClaimsRequest, model::claim::JwtClaimNames,
        },
    },
};

#[derive(Debug, Clone)]
pub struct AuthorizationRequestParams {
    pub response_type: String,
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
    client_request_repo: Arc<dyn ClientRequestRepository>,
    login_repo: Arc<dyn LoginRepository>,
    provider_service: Arc<OpenIdProviderService>,
    http_client: reqwest::Client,
    data_protector: Arc<dyn DataProtector>,
}

impl AuthorizeService {
    pub fn new(
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        client_request_repo: Arc<dyn ClientRequestRepository>,
        login_repo: Arc<dyn LoginRepository>,
        provider_service: Arc<OpenIdProviderService>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            client_repo,
            credential_repo,
            client_request_repo,
            login_repo,
            provider_service,
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .expect("request_uri HTTP client must build"),
            data_protector,
        }
    }
}

mod flow;
mod protection;
mod request_object;
mod validation;

#[cfg(test)]
mod tests;
