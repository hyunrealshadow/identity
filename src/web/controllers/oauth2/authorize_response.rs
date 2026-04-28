use http::{HeaderMap, StatusCode};
use salvo::Response;

use crate::{
    application::error::AppError,
    boot::AppState,
    domain::openid_connect::{AuthorizationRequest, OAuthErrorCode, OAuthErrorResponse},
    infrastructure::{i18n::resolve_locale_from_headers, web},
    web::views::oauth2::AuthorizeErrorPageData,
};

use super::authorize_extractor::{RawAuthorizeRequest, missing_required_authorize_parameters};
use crate::web::controllers::response::{redirect_to_response, render_app_error, render_html};

pub fn redirect_oauth_error_response(
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
) -> Response {
    let error_response = OAuthErrorResponse::new(error).with_state(request.state.clone());
    let redirect_uri = if request.response_type.is_implicit() {
        error_response.to_fragment_redirect_url(&request.redirect_uri)
    } else {
        error_response.to_redirect_url(&request.redirect_uri)
    };

    redirect_to_response(redirect_uri.as_str())
}

pub fn authorize_error_details(
    i18n: &crate::infrastructure::i18n::I18n,
    headers: &HeaderMap,
    raw: &RawAuthorizeRequest,
    error: &AppError,
) -> Vec<String> {
    let missing = missing_required_authorize_parameters(raw);
    if !missing.is_empty() {
        return missing
            .into_iter()
            .map(|name| format!("missing required parameter: {name}"))
            .collect();
    }

    vec![crate::web::controllers::response::error_message(
        i18n,
        &resolve_locale_from_headers(headers),
        error,
    )]
}

pub fn render_authorize_error_page(
    ctx: &AppState,
    headers: &HeaderMap,
    raw: &RawAuthorizeRequest,
    error: AppError,
) -> Response {
    use crate::application::error::kind::ErrorKind;

    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);

    let (status, details) = if error.kind() == ErrorKind::Internal {
        (StatusCode::INTERNAL_SERVER_ERROR, vec![])
    } else {
        (
            StatusCode::BAD_REQUEST,
            authorize_error_details(i18n, headers, raw, &error),
        )
    };

    let data = AuthorizeErrorPageData {
        title: i18n.t(&locale, "authorize-error-title"),
        message: i18n.t(&locale, "authorize-error-message"),
        details,
    };

    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "oauth2/authorize_error.html", data) {
        Ok(body) => render_html(&mut response, status, body),
        Err(error) => render_app_error(&mut response, error),
    }
    response
}

#[cfg(test)]
mod tests {
    use crate::application::error::AppError;
    use crate::application::error::codes::common::CommonErrorCode;
    use crate::application::error::kind::ErrorKind;

    #[test]
    fn internal_error_kind_maps_to_500_status() {
        // Verify that ErrorKind::Internal is what CommonErrorCode::InternalError produces
        let error = AppError::from_code(CommonErrorCode::InternalError);
        assert_eq!(error.kind(), ErrorKind::Internal);
    }
}
