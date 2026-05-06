use salvo::Router;

use super::shared::csrf_middleware;

mod authorize_endpoint;
mod authorize_extractor;
mod authorize_interaction;
mod authorize_response;
mod consent_endpoint;
mod continue_endpoint;
mod token_endpoint;
mod user_info_endpoint;

#[cfg(test)]
mod tests;

pub use authorize_extractor::{
    AuthorizeRequestExtractor, RawAuthorizeRequest, authorize_input_error,
};
pub use authorize_interaction::{FlowDecision, select_active_session};
pub use authorize_response::{
    finish_authorize_redirect, inline_script_csp_header_value, redirect_oauth_error_response,
    response_mode_from_value,
};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("oauth2/continue").get(continue_endpoint::continue_get))
        .push(
            Router::with_path("oauth2/authorize")
                .get(authorize_endpoint::authorize)
                .post(authorize_endpoint::authorize),
        )
        .push(Router::with_path("oauth2/token").post(token_endpoint::token))
        .push(
            Router::with_path("oauth2/userinfo")
                .get(user_info_endpoint::userinfo)
                .post(user_info_endpoint::userinfo_post),
        )
        .push(
            Router::with_path("oauth2/consent")
                .hoop(csrf_middleware())
                .get(consent_endpoint::consent_get)
                .post(consent_endpoint::consent_post),
        )
}
