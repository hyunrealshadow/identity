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
        client_authorization::{
            AccessTokenData, ClientAuthorization, ClientAuthorizationData,
            ClientAuthorizationRepository, ClientAuthorizationType, RefreshTokenData,
        },
        key::{KeyData, KeyJwkRepository, repository::KeyRepository},
        openid_connect::{
            OpenIdConnectClientRepository, OpenIdConnectCredentialData,
            OpenIdConnectCredentialRepository, OpenIdConnectCredentialType,
            model::claim::{JwtClaimNames, JwtTokenType, TokenUseValues},
        },
        user::{UserOid, repository::UserRepository},
    },
};

#[derive(Debug, Clone)]
pub struct AuthorizationCodeGrantParams {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenGrantParams {
    pub grant_type: String,
    pub refresh_token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: String,
}

pub struct TokenService {
    client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    key_repo: Arc<dyn KeyRepository>,
    key_jwk_repo: Arc<dyn KeyJwkRepository>,
    user_repo: Arc<dyn UserRepository>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    provider_service: Arc<OpenIdProviderService>,
    signing_algorithm_detector: Arc<dyn SigningAlgorithmDetector>,
    data_protector: Arc<dyn DataProtector>,
}

pub struct TokenServiceDependencies {
    pub client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
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
        Self {
            client_authorization_repo: deps.client_authorization_repo,
            key_repo: deps.key_repo,
            key_jwk_repo: deps.key_jwk_repo,
            user_repo: deps.user_repo,
            client_repo: deps.client_repo,
            credential_repo: deps.credential_repo,
            provider_service: deps.provider_service,
            signing_algorithm_detector: deps.signing_algorithm_detector,
            data_protector: deps.data_protector,
        }
    }
}

mod auth;
mod exchange;

pub(crate) use exchange::resolve_id_token_alg;

mod helpers;
mod signing;

use helpers::{
    client_id_from_assertion, decode_assertion_with_alg, decode_assertion_with_hmac_alg,
    decode_assertion_with_jwk, verify_pkce,
};

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
            token_type: "Bearer".to_owned(),
            expires_in: 3600,
            scope: "openid".to_owned(),
        };

        let value = serde_json::to_value(response).unwrap();

        assert!(value.get("id_token").is_none());
        assert!(value.get("refresh_token").is_none());
    }
}
