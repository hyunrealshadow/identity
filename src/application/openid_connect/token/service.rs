use crate::observability::NoopEventSink;

use super::*;

pub struct TokenService {
    pub(super) client_authentication: Arc<ClientAuthenticator>,
    pub(super) device_repo: Arc<dyn DeviceAuthorizationRepository>,
    pub(super) client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    pub(super) key_repo: Arc<dyn KeyRepository>,
    pub(super) key_jwk_repo: Arc<dyn KeyJwkRepository>,
    pub(super) user_repo: Arc<dyn UserRepository>,
    pub(super) client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub(super) credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    pub(super) provider_service: Arc<OpenIdProviderService>,
    pub(super) signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    pub(super) data_protector: Arc<dyn DataProtector>,
    pub(super) runtime_key_ring: Option<Arc<dyn RuntimeKeyRingProvider>>,
    pub(super) session_repo: Option<Arc<dyn SessionRepository>>,
    pub(super) events: Arc<dyn EventSink>,
}

pub struct TokenServiceDependencies {
    pub client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    pub device_repo: Arc<dyn DeviceAuthorizationRepository>,
    pub key_repo: Arc<dyn KeyRepository>,
    pub key_jwk_repo: Arc<dyn KeyJwkRepository>,
    pub user_repo: Arc<dyn UserRepository>,
    pub client_repo: Arc<dyn OpenIdConnectClientRepository>,
    pub credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    pub provider_service: Arc<OpenIdProviderService>,
    pub signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    pub data_protector: Arc<dyn DataProtector>,
}

impl TokenService {
    pub fn new(deps: TokenServiceDependencies) -> Self {
        let client_authentication =
            Arc::new(ClientAuthenticator::new(ClientAuthenticatorDependencies {
                client_repo: Arc::clone(&deps.client_repo),
                credential_repo: Arc::clone(&deps.credential_repo),
                provider_service: Arc::clone(&deps.provider_service),
            }));

        Self {
            client_authentication,
            device_repo: deps.device_repo,
            client_authorization_repo: deps.client_authorization_repo,
            key_repo: deps.key_repo,
            key_jwk_repo: deps.key_jwk_repo,
            user_repo: deps.user_repo,
            client_repo: deps.client_repo,
            credential_repo: deps.credential_repo,
            provider_service: deps.provider_service,
            signing_algorithm_detector: deps.signing_algorithm_detector,
            data_protector: deps.data_protector,
            runtime_key_ring: None,
            session_repo: None,
            events: Arc::new(NoopEventSink),
        }
    }

    /// Attach the key event and audit sink. Without an attached sink, business
    /// events are dropped silently, which keeps tests and tools independent
    /// from the observability pipeline.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    #[must_use]
    pub fn with_runtime_key_ring(
        mut self,
        runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
    ) -> Self {
        self.runtime_key_ring = Some(runtime_key_ring);
        self
    }

    #[must_use]
    pub fn with_session_repo(mut self, session_repo: Arc<dyn SessionRepository>) -> Self {
        self.session_repo = Some(session_repo);
        self
    }
}
