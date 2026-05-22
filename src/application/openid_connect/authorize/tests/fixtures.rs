use super::*;

mod clients;
mod repositories;
mod request_object;
mod services;

pub(super) use clients::{
    FoundClientRepository, InitiateLoginClientRepository, MissingClientRepository,
    RequestUriClientRepository, ScopedClientRepository, TEST_CLIENT_ID,
};
pub(super) use repositories::{
    InMemoryClientAuthorizationRepository, InMemoryCredentialRepository, InMemoryLoginRepository,
};
pub(super) use request_object::{
    authorize_service_with_public_key, authorize_service_with_request_uri, signed_request_object,
    signing_keypair, spawn_chunked_response_server, spawn_redirect_response_server,
};
pub(super) use services::{
    EmptyKeyJwkRepository, InMemoryKeyJwkRepository, StubKeyRepository, StubUserRepository,
    build_test_service, provider_service, test_data_protector, test_signing_algorithm_detector,
};

pub(super) fn params(scope: &str) -> AuthorizationRequestParams {
    AuthorizationRequestParams {
        response_type: "code".to_string(),
        response_mode: None,
        client_id: TEST_CLIENT_ID.to_string(),
        redirect_uri: "https://client.example.com/callback".to_string(),
        scope: scope.to_string(),
        state: "state123".to_string(),
        nonce: None,
        display: None,
        prompt: None,
        max_age: None,
        ui_locales: None,
        claims_locales: None,
        id_token_hint: None,
        login_hint: None,
        acr_values: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    }
}

pub(super) fn empty_optional_params() -> AuthorizationRequestParams {
    AuthorizationRequestParams {
        state: "state123".to_string(),
        ..params("openid profile")
    }
}
