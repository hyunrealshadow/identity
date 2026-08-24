use http::{HeaderMap, HeaderValue, StatusCode, header};
use salvo::Response;

use crate::{
    application::error::{AppError, kind::ErrorKind},
    boot::AppState,
    domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, OAuthErrorResponse, ResponseMode,
    },
    infrastructure::{i18n::resolve_locale_from_headers, web},
    web::views::oauth2::{ErrorPageData, FormPostField, FormPostPageData},
};

use super::extractor::RawAuthorizeRequest;
use crate::controllers::response::{redirect_to_response, render_app_error, render_html};
use crate::controllers::shared::generate_csp_nonce;

pub fn redirect_oauth_error_response(
    ctx: &AppState,
    headers: &HeaderMap,
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
) -> Response {
    let error_response = OAuthErrorResponse::new(error).with_state(request.state.clone());
    let response_mode = request.response_mode.unwrap_or_else(|| {
        if request.response_type.uses_front_channel_response() {
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
    if let Some(error_description) = &error_response.error_description {
        fields.push(FormPostField {
            name: "error_description".to_owned(),
            value: error_description.clone(),
        });
    }
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

pub fn finish_authorize_redirect(
    ctx: &AppState,
    headers: &HeaderMap,
    redirect_uri: &url::Url,
    response_mode: Option<ResponseMode>,
) -> Response {
    match response_mode {
        Some(ResponseMode::FormPost) => {
            render_form_post_redirect_response(ctx, headers, redirect_uri)
        }
        _ => redirect_to_response(redirect_uri.as_str()),
    }
}

pub fn inline_script_csp_header_value(nonce: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("default-src 'self'; script-src 'nonce-{nonce}'"))
        .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'"))
}

fn render_form_post_page(
    ctx: &AppState,
    headers: &HeaderMap,
    action: String,
    fields: Vec<FormPostField>,
) -> Response {
    let nonce = generate_csp_nonce();
    let data = FormPostPageData {
        title: "Completing sign-in".to_owned(),
        message: "Submitting the authorization response to the application.".to_owned(),
        action,
        fields,
        nonce: nonce.clone(),
    };

    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "oauth2/form_post.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, headers, ctx, error),
    }
    response.headers_mut().insert(
        header::HeaderName::from_static("content-security-policy"),
        inline_script_csp_header_value(&nonce),
    );
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

fn authorize_error_status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorKind::Gone => StatusCode::GONE,
        _ => StatusCode::BAD_REQUEST,
    }
}

pub(super) fn authorize_oauth_error_code(error: &AppError) -> OAuthErrorCode {
    use identity_application::error::{code::AppErrorCode, codes::authorize::AuthorizeErrorCode};

    if error.kind() == ErrorKind::Internal {
        return OAuthErrorCode::ServerError;
    }

    match error.code() {
        code if code == AuthorizeErrorCode::ResponseTypeInvalid.code() => {
            OAuthErrorCode::UnsupportedResponseType
        }
        code if code == AuthorizeErrorCode::ScopeInvalid.code()
            || code == AuthorizeErrorCode::OpenidScopeRequired.code()
            || code == AuthorizeErrorCode::ScopeNotAssignedToClient.code() =>
        {
            OAuthErrorCode::InvalidScope
        }
        code if code == AuthorizeErrorCode::RequestUriInvalid.code()
            || (AuthorizeErrorCode::RequestUriNotHttps.code()
                ..=AuthorizeErrorCode::RequestUriReadFailed.code())
                .contains(&code) =>
        {
            OAuthErrorCode::InvalidRequestUri
        }
        code if (AuthorizeErrorCode::RequestObjectHeaderInvalid.code()
            ..=AuthorizeErrorCode::RequestObjectPayloadInvalid.code())
            .contains(&code) =>
        {
            OAuthErrorCode::InvalidRequestObject
        }
        code if code == AuthorizeErrorCode::RequestObjectEncryptionUnsupported.code() => {
            OAuthErrorCode::RequestNotSupported
        }
        _ => OAuthErrorCode::InvalidRequest,
    }
}

pub fn render_authorize_error_page(
    ctx: &AppState,
    headers: &HeaderMap,
    _raw: &RawAuthorizeRequest,
    error: AppError,
) -> Response {
    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);
    let status = authorize_error_status(error.kind());
    let oauth_error_code = authorize_oauth_error_code(&error);
    let message = crate::controllers::response::error_message(i18n, &locale, &error);

    let data = ErrorPageData {
        status_code: status.as_u16(),
        oauth_error_code: Some(oauth_error_code.to_string()),
        error_code: Some(error.code()),
        title: i18n.t(&locale, "error-page-title"),
        message,
        details: Vec::new(),
    };

    let mut response = Response::new();
    match web::tera::render_view(ctx, headers, "error.html", data) {
        Ok(body) => render_html(&mut response, status, body),
        Err(error) => render_app_error(&mut response, headers, ctx, error),
    }
    response
}

#[cfg(test)]
mod tests {
    use http::{HeaderValue, StatusCode};
    use identity_application::error::AppError;
    use identity_application::error::codes::common::CommonErrorCode;
    use identity_application::error::kind::ErrorKind;
    use identity_domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, ResponseMode, ResponseType, ScopeSet,
    };
    use salvo::test::ResponseExt;

    use super::{authorize_error_status, authorize_oauth_error_code};

    #[test]
    fn internal_error_kind_maps_to_500_status() {
        // Verify that ErrorKind::Internal is what CommonErrorCode::InternalError produces
        let error = AppError::from_code(CommonErrorCode::InternalError);
        assert_eq!(error.kind(), ErrorKind::Internal);
    }

    #[test]
    fn authorize_error_status_preserves_http_error_semantics() {
        assert_eq!(
            authorize_error_status(ErrorKind::Validation),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(authorize_error_status(ErrorKind::Gone), StatusCode::GONE);
        assert_eq!(
            authorize_error_status(ErrorKind::Internal),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn authorize_oauth_error_code_maps_protocol_errors() {
        use identity_application::error::codes::authorize::AuthorizeErrorCode;

        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(
                AuthorizeErrorCode::ResponseTypeInvalid
            )),
            OAuthErrorCode::UnsupportedResponseType
        );
        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(AuthorizeErrorCode::ScopeInvalid)),
            OAuthErrorCode::InvalidScope
        );
        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(CommonErrorCode::InternalError)),
            OAuthErrorCode::ServerError
        );
    }

    #[tokio::test]
    async fn form_post_error_uses_autopost_template() {
        let ctx = identity_infrastructure::test_app_state_with_mock_settings().await;
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
        assert!(
            body.contains(
                "name=\"error_description\" value=\"The user must sign in to continue.\""
            ),
            "{body}"
        );
        assert!(body.contains("name=\"state\" value=\"state\""), "{body}");
        assert!(body.contains("<noscript>"), "{body}");
        assert!(body.contains("type=\"submit\""), "{body}");
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

    #[tokio::test]
    async fn finish_authorize_redirect_renders_form_post_page() {
        let ctx = identity_infrastructure::test_app_state_with_mock_settings().await;
        let headers = http::HeaderMap::new();
        let redirect_uri =
            url::Url::parse("https://client.example.com/callback#code=abc&state=xyz").unwrap();

        let response = super::finish_authorize_redirect(
            &ctx,
            &headers,
            &redirect_uri,
            Some(identity_domain::openid_connect::ResponseMode::FormPost),
        );

        assert_eq!(response.status_code, Some(http::StatusCode::OK));
    }

    #[tokio::test]
    async fn finish_authorize_redirect_uses_http_redirect_for_non_form_post() {
        let ctx = identity_infrastructure::test_app_state_with_mock_settings().await;
        let headers = http::HeaderMap::new();
        let redirect_uri =
            url::Url::parse("https://client.example.com/callback?code=abc&state=xyz").unwrap();

        let response = super::finish_authorize_redirect(&ctx, &headers, &redirect_uri, None);

        assert_eq!(response.status_code, Some(http::StatusCode::SEE_OTHER));
    }

    #[test]
    fn inline_script_csp_header_value_allows_inline_scripts() {
        let nonce = "test-nonce-123";
        assert_eq!(
            super::inline_script_csp_header_value(nonce),
            HeaderValue::from_static("default-src 'self'; script-src 'nonce-test-nonce-123'")
        );
    }
}
