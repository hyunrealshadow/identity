use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::jwt;
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        data_protection::DataProtector,
        error::{
            AppError,
            codes::{
                auth::AuthErrorCode, authorize::AuthorizeErrorCode,
                authorize_http::AuthorizeHttpErrorCode,
            },
        },
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    },
    domain::{
        auth::repository::LoginRepository,
        client_authorization::{ClientAuthorizationRepository, ClientAuthorizationType},
        key::{
            JweContentEncryption, JwsAlgorithm, KeyData, KeyJwkRepository,
            repository::KeyRepository,
        },
        openid_connect::{
            AuthorizationRequest, AuthorizationRequestData, ClaimRequestMap, CodeChallengeMethod,
            Display, OpenIdConnectClient, OpenIdConnectClientRepository,
            OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
            OpenIdConnectCredentialType, PromptValue, ResponseMode, ResponseType, ScopeSet,
            model::authorization_request::ClaimsRequest, model::claim::JwtClaimNames,
        },
        user::{UserOid, repository::UserRepository},
    },
};

pub use identity_domain::openid_connect::model::authorization_request::AuthorizationRequestParams;

#[derive(Clone)]
pub struct AuthorizeService {
    scope_catalog:
        Option<Arc<dyn identity_domain::openid_connect::scope_catalog::ScopeCatalogRepository>>,
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
    events: Arc<dyn crate::observability::EventSink>,
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
    pub http_client: reqwest::Client,
}

impl AuthorizeService {
    pub fn issuer(&self) -> Result<Url, AppError> {
        self.provider_service.issuer()
    }

    pub fn new(deps: AuthorizeServiceDependencies) -> Self {
        Self {
            scope_catalog: None,
            client_repo: deps.client_repo,
            credential_repo: deps.credential_repo,
            client_authorization_repo: deps.client_authorization_repo,
            login_repo: deps.login_repo,
            user_repo: deps.user_repo,
            key_repo: deps.key_repo,
            key_jwk_repo: deps.key_jwk_repo,
            provider_service: deps.provider_service,
            signing_algorithm_detector: deps.signing_algorithm_detector,
            http_client: deps.http_client,
            data_protector: deps.data_protector,
            events: Arc::new(crate::observability::NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_scope_catalog(
        mut self,
        repository: Arc<dyn identity_domain::openid_connect::scope_catalog::ScopeCatalogRepository>,
    ) -> Self {
        self.scope_catalog = Some(repository);
        self
    }

    pub async fn scope_descriptions(
        &self,
        scope: &ScopeSet,
    ) -> Result<Vec<identity_domain::openid_connect::scope_catalog::ScopeDescription>, AppError>
    {
        let repository = self
            .scope_catalog
            .as_ref()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::LoadRequestFailed))?;
        repository
            .find_by_names(&scope.names())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoadRequestFailed).with_source(error)
            })
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn crate::observability::EventSink>) -> Self {
        self.events = events;
        self
    }
}

mod flow;
pub use flow::AuthorizationApproval;
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
