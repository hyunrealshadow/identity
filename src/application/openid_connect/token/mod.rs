use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use helpers::{client_id_from_assertion, verify_pkce};
use josekit::{jws::JwsHeader, jwt, jwt::JwtPayload};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    application::{
        error::{AppError, codes::token::TokenErrorCode},
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    },
    data_protection::DataProtector,
    domain::{
        auth::repository::SessionRepository,
        client_authorization::{
            AccessTokenData, ClientAuthorizationData, ClientAuthorizationRepository,
            ClientAuthorizationType, DeviceAuthorizationRepository, DevicePollOutcome,
            DeviceRequestStatus, PreparedAuthorizationRecord, RefreshTokenData, device_code_digest,
        },
        key::{
            JweContentEncryption, JwsAlgorithm, KeyData, KeyJwkRepository,
            repository::KeyRepository,
        },
        openid_connect::{
            GrantType, OpenIdConnectClient, OpenIdConnectClientRepository,
            OpenIdConnectCredentialRepository, ScopeSet,
            model::claim::{JwtClaimNames, JwtTokenType, TokenUse},
        },
        user::{User, UserOid, repository::UserRepository},
    },
    key::runtime::RuntimeKeyRingProvider,
    observability::EventSink,
    openid_connect::client_authentication::{ClientAuthenticator, ClientAuthenticatorDependencies},
};

mod request;
mod service;
pub use request::{
    AuthorizationCodeGrantParams, ClientCredentialsGrantParams, DeviceCodeGrantParams,
    RefreshTokenGrantParams, TokenIntrospectionParams, TokenResponse, TokenRevocationParams,
    TokenType,
};
pub use service::{TokenService, TokenServiceDependencies};

mod authorization_code;
mod client_credentials;
mod device;
mod encryption;
mod exchange;
mod introspection;
mod refresh_token;
mod revocation;

pub(crate) use exchange::resolve_client_id;

pub(crate) mod helpers;
mod signing;
mod signing_key;

#[cfg(test)]
mod tests;
