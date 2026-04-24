use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jws::{ES256, ES256K, ES384, ES512, EdDSA, JwsHeader, RS256, RS384, RS512},
    jwt,
    jwt::JwtPayload,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::application::data_protection::DataProtector;

use crate::{
    application::{
        error::{AppError, codes::token::TokenErrorCode},
        openid_connect::provider::OpenIdProviderService,
    },
    domain::{
        client_request::{
            AuthorizationCodeData, ClientRequestRepository, ClientRequestType, RefreshTokenData,
        },
        key::{KeyData, repository::KeyRepository},
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
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: String,
}

pub struct TokenService {
    client_request_repo: Arc<dyn ClientRequestRepository>,
    key_repo: Arc<dyn KeyRepository>,
    user_repo: Arc<dyn UserRepository>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    provider_service: Arc<OpenIdProviderService>,
    data_protector: Arc<dyn DataProtector>,
}

impl TokenService {
    pub fn new(
        client_request_repo: Arc<dyn ClientRequestRepository>,
        key_repo: Arc<dyn KeyRepository>,
        user_repo: Arc<dyn UserRepository>,
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        provider_service: Arc<OpenIdProviderService>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            client_request_repo,
            key_repo,
            user_repo,
            client_repo,
            credential_repo,
            provider_service,
            data_protector,
        }
    }
}

mod auth;
mod exchange;
mod helpers;
mod signing;

use helpers::{constant_time_compare, decode_assertion_with_alg, verify_pkce};

#[cfg(test)]
mod tests;
