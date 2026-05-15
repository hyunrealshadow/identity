use salvo::Router;

use super::shared::csrf_middleware;

mod authorize_endpoint;
mod consent_endpoint;
mod continue_endpoint;
mod logout_endpoint;
mod session_endpoint;
mod token_endpoint;
mod user_info_endpoint;

#[cfg(test)]
mod tests;

pub use authorize_endpoint::{
    AuthorizeRequestExtractor, FlowDecision, RawAuthorizeRequest, authorize_input_error,
    finish_authorize_redirect, inline_script_csp_header_value, redirect_oauth_error_response,
    response_mode_from_value, select_active_session,
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
        .push(Router::with_path("oauth2/check_session").get(session_endpoint::check_session_iframe))
        .push(
            Router::with_path("oauth2/logout")
                .get(logout_endpoint::logout_get)
                .post(logout_endpoint::logout_post),
        )
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
