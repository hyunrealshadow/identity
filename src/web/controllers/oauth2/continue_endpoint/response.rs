use http::HeaderMap;

use crate::{
    application::error::{AppError, codes::authorize::AuthorizeErrorCode},
    controllers::response::redirect_to_response,
    domain::openid_connect::{AuthorizationRequestData, OAuthErrorCode, OAuthErrorResponse},
};

use crate::controllers::oauth2::authorize_endpoint::render_form_post_response;

pub(super) fn continue_login_redirect(
    ctx: &identity_infrastructure::AppState,
    login_id: &str,
) -> Result<salvo::Response, AppError> {
    crate::controllers::shared::login_redirect(ctx, login_id)
}

pub(super) fn continue_consent_redirect(
    ctx: &identity_infrastructure::AppState,
    login_id: &str,
) -> Result<salvo::Response, AppError> {
    crate::controllers::shared::consent_redirect(ctx, login_id)
}

pub(super) fn continue_oauth_error_response(
    ctx: &identity_infrastructure::AppState,
    headers: &HeaderMap,
    request: &AuthorizationRequestData,
    error: OAuthErrorCode,
) -> Result<salvo::Response, AppError> {
    let redirect_uri = url::Url::parse(&request.redirect_uri).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
    })?;
    let response_type = request.response_type.clone();
    let error_response = OAuthErrorResponse::new(error).with_state(request.state.clone());

    Ok(match request.response_mode {
        Some(identity_domain::openid_connect::ResponseMode::FormPost) => {
            render_form_post_response(ctx, headers, &redirect_uri, &error_response)
        }
        _ if response_type.uses_front_channel_response() => redirect_to_response(
            error_response
                .to_fragment_redirect_url(&redirect_uri)
                .as_str(),
        ),
        _ => redirect_to_response(error_response.to_redirect_url(&redirect_uri).as_str()),
    })
}
