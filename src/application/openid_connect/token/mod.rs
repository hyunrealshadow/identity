use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{jws::JwsHeader, jwt, jwt::JwtPayload};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::data_protection::DataProtector;

use crate::{
    application::{
        error::{AppError, codes::token::TokenErrorCode},
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    },
    domain::{
        auth::repository::SessionRepository,
        client_authorization::{
            AccessTokenData, ClientAuthorization, ClientAuthorizationData,
            ClientAuthorizationRepository, ClientAuthorizationType, DeviceAuthorizationRepository,
            DevicePollOutcome, DeviceRequestStatus, PreparedAuthorizationRecord, RefreshTokenData,
            device_code_digest,
        },
        key::{
            JwaEncryptionAlgorithm, JweContentEncryption, JwsAlgorithm, KeyData, KeyJwkRepository,
            repository::KeyRepository,
        },
        openid_connect::{
            GrantType, OpenIdConnectClient, OpenIdConnectClientRepository,
            OpenIdConnectCredentialRepository, ScopeSet,
            model::claim::{JwtClaimNames, JwtTokenType, TokenUse},
        },
        user::{User, UserOid, repository::UserRepository},
    },
};

#[derive(Debug, Clone)]
pub struct AuthorizationCodeGrantParams {
    pub code: String,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceCodeGrantParams {
    pub device_code: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenGrantParams {
    pub refresh_token: String,
    /// Optional narrowing of the originally granted scope (RFC 6749 §6).
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientCredentialsGrantParams {
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_basic: bool,
    pub client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: TokenType,
    pub expires_in: i32,
    pub scope: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum TokenType {
    #[serde(rename = "Bearer")]
    Bearer,
}

pub struct TokenService {
    client_authentication: Arc<crate::openid_connect::client_authentication::ClientAuthenticator>,
    device_repo: Arc<dyn DeviceAuthorizationRepository>,
    client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    key_repo: Arc<dyn KeyRepository>,
    key_jwk_repo: Arc<dyn KeyJwkRepository>,
    user_repo: Arc<dyn UserRepository>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    provider_service: Arc<OpenIdProviderService>,
    signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    data_protector: Arc<dyn DataProtector>,
    runtime_key_ring: Option<Arc<dyn crate::key::runtime::RuntimeKeyRingProvider>>,
    session_repo: Option<Arc<dyn SessionRepository>>,
    events: Arc<dyn crate::observability::EventSink>,
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
        let client_authentication = Arc::new(
            crate::openid_connect::client_authentication::ClientAuthenticator::new(
                crate::openid_connect::client_authentication::ClientAuthenticatorDependencies {
                    client_repo: Arc::clone(&deps.client_repo),
                    credential_repo: Arc::clone(&deps.credential_repo),
                    provider_service: Arc::clone(&deps.provider_service),
                },
            ),
        );

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
            events: Arc::new(crate::observability::NoopEventSink),
        }
    }

    /// Attach the key event and audit sink. Without an attached sink, business
    /// events are dropped silently, which keeps tests and tools independent
    /// from the observability pipeline.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn crate::observability::EventSink>) -> Self {
        self.events = events;
        self
    }

    #[must_use]
    pub fn with_runtime_key_ring(
        mut self,
        runtime_key_ring: Arc<dyn crate::key::runtime::RuntimeKeyRingProvider>,
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

mod client_credentials;
mod device;
mod exchange;

pub(crate) use exchange::{resolve_client_id, resolve_id_token_alg};

pub(crate) mod helpers;
mod signing;

use helpers::{client_id_from_assertion, verify_pkce};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn token_response_omits_absent_optional_tokens() {
        let response = TokenResponse {
            access_token: "access".to_owned(),
            id_token: None,
            refresh_token: None,
            token_type: TokenType::Bearer,
            expires_in: 3600,
            scope: "openid".to_owned(),
        };

        let value = serde_json::to_value(response).unwrap();

        assert!(value.get("id_token").is_none());
        assert!(value.get("refresh_token").is_none());
    }
}
