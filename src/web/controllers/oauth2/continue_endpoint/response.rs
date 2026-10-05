use crate::controllers::shared::consent_redirect;
use crate::controllers::shared::login_redirect;
use http::HeaderMap;
use identity_domain::openid_connect::ResponseMode;
use identity_infrastructure::AppState;
use salvo::Response;
use url::Url;

use crate::{
    application::error::{AppError, codes::authorize::AuthorizeErrorCode},
    controllers::response::redirect_to_response,
    domain::openid_connect::{AuthorizationRequestData, OAuthErrorCode},
};

use crate::controllers::oauth2::authorization_error::oauth_error_response;
use crate::controllers::oauth2::authorize_endpoint::render_form_post_response;

pub(super) fn continue_login_redirect(
    ctx: &AppState,
    login_id: &str,
) -> Result<Response, AppError> {
    login_redirect(ctx, login_id)
}

pub(super) fn continue_consent_redirect(
    ctx: &AppState,
    login_id: &str,
) -> Result<Response, AppError> {
    consent_redirect(ctx, login_id)
}

pub(super) fn continue_oauth_error_response(
    ctx: &AppState,
    headers: &HeaderMap,
    request: &AuthorizationRequestData,
    error: OAuthErrorCode,
) -> Result<Response, AppError> {
    let redirect_uri = Url::parse(&request.redirect_uri).map_err(AppError::map_source(
        AuthorizeErrorCode::StoredRedirectUriInvalid,
    ))?;
    let response_type = request.response_type.clone();
    let error_response = oauth_error_response(ctx, headers, error, None)
        .with_state(request.state.clone())
        .with_issuer(ctx.services().oidc_authorize().issuer()?.to_string());

    Ok(match request.response_mode {
        Some(ResponseMode::FormPost) => {
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
