use http::{HeaderMap, StatusCode};
use salvo::Response;

use crate::{
    application::error::AppError,
    boot::AppState,
    domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, OAuthErrorResponse, ResponseMode,
    },
    infrastructure::{i18n::resolve_locale_from_headers, web},
    web::views::oauth2::{AuthorizeErrorPageData, FormPostField, FormPostPageData},
};

use super::authorize_extractor::{RawAuthorizeRequest, missing_required_authorize_parameters};
use crate::web::controllers::response::{redirect_to_response, render_app_error, render_html};

pub fn redirect_oauth_error_response(
    ctx: &AppState,
    headers: &HeaderMap,
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
) -> Response {
    let error_response = OAuthErrorResponse::new(error).with_state(request.state.clone());
    let response_mode = request.response_mode.unwrap_or_else(|| {
        if request.response_type.is_implicit() {
            ResponseMode::Fragment
        } else {
            ResponseMode::Query
        }
    });

    if response_mode == ResponseMode::FormPost {
        return render_form_post_response(ctx, headers, &request.redirect_uri, &error_response);
    }

    let redirect_uri = match response_mode {
        ResponseMode::Query => error_response.to_redirect_url(&request.redirect_uri),
        ResponseMode::Fragment => error_response.to_fragment_redirect_url(&request.redirect_uri),
        ResponseMode::FormPost => unreachable!("form_post returned above"),
    };

    redirect_to_response(redirect_uri.as_str())
}

pub fn render_form_post_response(
    ctx: &AppState,
    headers: &HeaderMap,
    redirect_uri: &url::Url,
    error_response: &OAuthErrorResponse,
) -> Response {
    let mut fields = vec![FormPostField {
        name: "error".to_owned(),
        value: error_response.error.to_string(),
    }];
    if let Some(state) = &error_response.state {
        fields.push(FormPostField {
            name: "state".to_owned(),
            value: state.clone(),
        });
    }

    render_form_post_page(ctx, headers, redirect_uri.to_string(), fields)
}

pub fn render_form_post_redirect_response(
    ctx: &AppState,
    headers: &HeaderMap,
    redirect_uri: &url::Url,
) -> Response {
    let (action, fields) = form_post_action_and_fields(redirect_uri);
    render_form_post_page(ctx, headers, action, fields)
}

fn render_form_post_page(
    ctx: &AppState,
    headers: &HeaderMap,
    action: String,
    fields: Vec<FormPostField>,
) -> Response {
    let data = FormPostPageData {
        title: "Completing sign-in".to_owned(),
        message: "Submitting the authorization response to the application.".to_owned(),
        action,
        fields,
    };

    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "oauth2/form_post.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, error),
    }
    response
}

fn form_post_action_and_fields(redirect_uri: &url::Url) -> (String, Vec<FormPostField>) {
    let mut action = redirect_uri.clone();
    let pairs = action
        .fragment()
        .map(|fragment| {
            url::form_urlencoded::parse(fragment.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            action
                .query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        });

    action.set_query(None);
    action.set_fragment(None);

    let fields = pairs
        .into_iter()
        .map(|(name, value)| FormPostField { name, value })
        .collect();

    (action.to_string(), fields)
}

pub fn response_mode_from_value(value: Option<&str>) -> Option<ResponseMode> {
    value.and_then(|mode| mode.parse::<ResponseMode>().ok())
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
    use crate::domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, ResponseMode, ResponseType, ScopeSet,
    };
    use salvo::test::ResponseExt;

    #[test]
    fn internal_error_kind_maps_to_500_status() {
        // Verify that ErrorKind::Internal is what CommonErrorCode::InternalError produces
        let error = AppError::from_code(CommonErrorCode::InternalError);
        assert_eq!(error.kind(), ErrorKind::Internal);
    }

    #[tokio::test]
    async fn form_post_error_uses_autopost_template() {
        let ctx = crate::boot::test_app_state_with_mock_settings().await;
        let headers = http::HeaderMap::new();
        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            response_mode: Some(ResponseMode::FormPost),
            client_id: uuid::Uuid::nil(),
            redirect_uri: url::Url::parse("https://client.example.com/callback").unwrap(),
            scope: ScopeSet::parse("openid").unwrap(),
            state: "state".to_string(),
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
            request_uri: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let mut response = super::redirect_oauth_error_response(
            &ctx,
            &headers,
            &request,
            OAuthErrorCode::LoginRequired,
        );
        let body = response.take_string().await.unwrap();

        assert!(body.contains("method=\"post\""), "{body}");
        assert!(
            body.contains("action=\"https:&#x2F;&#x2F;client.example.com&#x2F;callback\""),
            "{body}"
        );
        assert!(
            body.contains("name=\"error\" value=\"login_required\""),
            "{body}"
        );
        assert!(body.contains("name=\"state\" value=\"state\""), "{body}");
        assert!(body.contains("auth-card"), "{body}");
    }

    #[test]
    fn form_post_action_and_fields_moves_query_into_fields() {
        let redirect_uri =
            url::Url::parse("https://client.example.com/callback?code=abc&state=xyz").unwrap();

        let (action, fields) = super::form_post_action_and_fields(&redirect_uri);

        assert_eq!(action, "https://client.example.com/callback");
        assert_eq!(fields[0].name, "code");
        assert_eq!(fields[0].value, "abc");
        assert_eq!(fields[1].name, "state");
        assert_eq!(fields[1].value, "xyz");
    }
}
