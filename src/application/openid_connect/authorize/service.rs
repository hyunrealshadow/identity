use crate::observability::NoopEventSink;

use super::*;

#[derive(Clone)]
pub struct AuthorizeService {
    pub(super) scope_catalog: Option<Arc<dyn ScopeCatalogRepository>>,
    pub(super) client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub(super) credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    pub(super) client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    pub(super) login_repo: Arc<dyn LoginRepository>,
    pub(super) user_repo: Arc<dyn UserRepository>,
    pub(super) key_repo: Arc<dyn KeyRepository>,
    pub(super) key_jwk_repo: Arc<dyn KeyJwkRepository>,
    pub(super) provider_service: Arc<OpenIdProviderService>,
    pub(super) signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    pub(super) http_client: Client,
    pub(super) data_protector: Arc<dyn DataProtector>,
    pub(super) events: Arc<dyn EventSink>,
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
    pub http_client: Client,
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
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_scope_catalog(mut self, repository: Arc<dyn ScopeCatalogRepository>) -> Self {
        self.scope_catalog = Some(repository);
        self
    }

    pub async fn scope_descriptions(
        &self,
        scope: &ScopeSet,
    ) -> Result<Vec<ScopeDescription>, AppError> {
        let repository = self
            .scope_catalog
            .as_ref()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::LoadRequestFailed))?;
        let descriptions = repository
            .find_by_names(&scope.names())
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?;
        if scope
            .names()
            .iter()
            .any(|name| !descriptions.iter().any(|item| item.name == *name))
        {
            return Err(AppError::from_code(AuthorizeErrorCode::ScopeInvalid));
        }
        Ok(descriptions)
    }

    /// Attach the key event and audit sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }
}
