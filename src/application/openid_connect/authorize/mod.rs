use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_domain::openid_connect::scope_catalog::{ScopeCatalogRepository, ScopeDescription};
use josekit::jwt;
use reqwest::Client;
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
            AuthorizationRequest, AuthorizationRequestData, ClaimRequestMap, OpenIdConnectClient,
            OpenIdConnectClientRepository, OpenIdConnectCredentialData,
            OpenIdConnectCredentialRepository, OpenIdConnectCredentialType, ResponseType, ScopeSet,
            model::{authorization_request::ClaimsRequest, claim::JwtClaimNames},
        },
        user::{UserOid, repository::UserRepository},
    },
    observability::EventSink,
};

pub use identity_domain::openid_connect::model::authorization_request::AuthorizationRequestParams;

mod service;
pub use service::{AuthorizeService, AuthorizeServiceDependencies};

mod flow;
pub use flow::{AuthorizationApproval, ContinueContext};
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
