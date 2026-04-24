use salvo::Router;

mod authorize_endpoint;
mod authorize_extractor;
mod authorize_interaction;
mod authorize_response;
mod consent_endpoint;
mod token_endpoint;
mod user_info_endpoint;

pub use authorize_extractor::{
    AuthorizeRequestExtractor, RawAuthorizeRequest, authorize_input_error,
};
pub use authorize_interaction::{FlowDecision, select_active_session};
pub use authorize_response::redirect_oauth_error_response;

pub fn routes() -> Router {
    Router::new()
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
            Router::with_path("oauth2/authorize/consent")
                .get(consent_endpoint::consent_page)
                .post(consent_endpoint::consent_submit),
        )
        .push(
            Router::with_path("api/oauth2/authorize/consent")
                .get(consent_endpoint::consent_api)
                .post(consent_endpoint::consent_api_submit),
        )
}
