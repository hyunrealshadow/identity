use axum::{
    Router,
    routing::{get, post},
};

use crate::boot::AppState;

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

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/oauth2/authorize",
            get(authorize_endpoint::authorize).post(authorize_endpoint::authorize),
        )
        .route("/oauth2/token", post(token_endpoint::token))
        .route(
            "/oauth2/userinfo",
            get(user_info_endpoint::userinfo).post(user_info_endpoint::userinfo_post),
        )
        .route(
            "/oauth2/authorize/consent",
            get(consent_endpoint::consent_page).post(consent_endpoint::consent_submit),
        )
        .route(
            "/api/oauth2/authorize/consent",
            get(consent_endpoint::consent_api).post(consent_endpoint::consent_api_submit),
        )
}
