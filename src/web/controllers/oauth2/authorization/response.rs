use http::{HeaderMap, StatusCode, header};
use identity_domain::openid_connect::{AuthorizationRequestData, ResponseType, ScopeSet};
use salvo::{Depot, Request, Response, Writer, async_trait};
use url::{Url, form_urlencoded::parse};
use uuid::Uuid;

use super::{
    error::{
        authorize_error_status, authorize_oauth_error_code, localized_authorize_error_response,
        oauth_error_response,
    },
    interaction::FlowDecision,
    request::RawAuthorizeRequest,
};
use crate::{
    application::error::{AppError, codes::authorize::AuthorizeErrorCode},
    boot::AppState,
    controllers::{
        response::{
            WebError, app_state, error_message, log_app_error, redirect_to_response,
            render_app_error, render_html,
        },
        shared::{generate_csp_nonce, inline_script_csp_header_value, login_redirect},
    },
    domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, OAuthErrorResponse, ResponseMode,
    },
    infrastructure::{i18n::resolve_locale_from_headers, web},
    web::views::oauth2::{ErrorPageData, FormPostField, FormPostPageData},
};

pub fn redirect_oauth_error_response(
    ctx: &AppState,
    headers: &HeaderMap,
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
) -> Response {
    let issuer = match ctx.services().oidc_authorize().issuer() {
        Ok(issuer) => issuer,
        Err(error) => {
            return render_authorize_error_page(ctx, headers, error);
        }
    };
    let error_response = oauth_error_response(ctx, headers, error, None)
        .with_state(request.state.clone())
        .with_issuer(issuer.to_string());
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
    redirect_uri: &Url,
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
    if let Some(issuer) = &error_response.issuer {
        fields.push(FormPostField {
            name: "iss".to_owned(),
            value: issuer.clone(),
        });
    }

    render_form_post_page(ctx, headers, redirect_uri.to_string(), fields)
}

pub fn render_form_post_redirect_response(
    ctx: &AppState,
    headers: &HeaderMap,
    redirect_uri: &Url,
) -> Response {
    let (action, fields) = form_post_action_and_fields(redirect_uri);
    render_form_post_page(ctx, headers, action, fields)
}

pub fn finish_authorize_redirect(
    ctx: &AppState,
    headers: &HeaderMap,
    redirect_uri: &Url,
    response_mode: Option<ResponseMode>,
) -> Response {
    match response_mode {
        Some(ResponseMode::FormPost) => {
            render_form_post_redirect_response(ctx, headers, redirect_uri)
        }
        _ => redirect_to_response(redirect_uri.as_str()),
    }
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

fn form_post_action_and_fields(redirect_uri: &Url) -> (String, Vec<FormPostField>) {
    let mut action = redirect_uri.clone();
    let pairs = action
        .fragment()
        .map(|fragment| {
            parse(fragment.as_bytes())
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

pub fn render_authorize_error_page(
    ctx: &AppState,
    headers: &HeaderMap,
    error: AppError,
) -> Response {
    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);
    let status = authorize_error_status(error.kind());
    let oauth_error_code = authorize_oauth_error_code(&error);
    let message = error_message(i18n, &locale, &error);

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

async fn render_error(
    ctx: &AppState,
    headers: &HeaderMap,
    raw: &RawAuthorizeRequest,
    error: AppError,
) -> Response {
    log_app_error(&error, "authorization request failed");

    let mut resolved_raw = raw.clone();
    if resolved_raw
        .redirect_uri
        .as_deref()
        .is_none_or(str::is_empty)
        && resolved_raw
            .scope
            .as_deref()
            .is_none_or(|scope| !ScopeSet::parse(scope).is_ok_and(|scope| scope.contains_openid()))
        && let Some(client_oid) = resolved_raw
            .client_id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok())
        && let Some(client) = ctx
            .services()
            .oidc_client_repo()
            .find_by_oid(client_oid)
            .await
            .unwrap_or(None)
        && let Some(only_uri) = client.single_redirect_uri()
    {
        resolved_raw.redirect_uri = Some(only_uri.to_owned());
    }
    let raw = &resolved_raw;

    let can_redirect = raw.redirect_uri.as_deref().is_some_and(|u| !u.is_empty())
        && raw.client_id.as_deref().is_some_and(|c| !c.is_empty());

    if can_redirect
        && let Some(redirect_uri) = raw.redirect_uri.as_deref()
        && let Ok(uri) = Url::parse(redirect_uri)
    {
        let client_oid = raw
            .client_id
            .as_deref()
            .and_then(|cid| Uuid::parse_str(cid).ok());

        if let Some(client_oid) = client_oid {
            let client = ctx
                .services()
                .oidc_client_repo()
                .find_by_oid(client_oid)
                .await
                .unwrap_or(None);
            if !client.is_some_and(|c| c.has_redirect_uri_str(redirect_uri)) {
                return render_authorize_error_page(ctx, headers, error);
            }
        } else {
            return render_authorize_error_page(ctx, headers, error);
        }

        let issuer = match ctx.services().oidc_authorize().issuer() {
            Ok(issuer) => issuer,
            Err(error) => return render_authorize_error_page(ctx, headers, error),
        };
        let error_response = localized_authorize_error_response(ctx, headers, &error)
            .with_issuer(issuer.to_string());
        let error_response = if let Some(s) = raw.state.clone() {
            error_response.with_state(s)
        } else {
            error_response
        };
        if raw.response_mode.as_deref() == Some("form_post") {
            return render_form_post_response(ctx, headers, &uri, &error_response);
        }

        let error_response = match raw
            .response_type
            .as_deref()
            .and_then(|value| value.parse::<ResponseType>().ok())
        {
            Some(response_type) if response_type.uses_front_channel_response() => {
                error_response.to_fragment_redirect_url(&uri)
            }
            _ => error_response.to_redirect_url(&uri),
        };
        return redirect_to_response(error_response.as_str());
    }

    render_authorize_error_page(ctx, headers, error)
}

/// Uses normalized parameters; render_error verifies the redirect against
/// the registered client before sending a protocol error there.
pub(super) struct AuthorizationWebError(pub(super) AppError);

impl From<AppError> for AuthorizationWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for AuthorizationWebError {
    async fn write(self, req: &mut Request, depot: &mut Depot, res: &mut Response) {
        match (app_state(depot), depot.get_typed::<RawAuthorizeRequest>()) {
            (Ok(ctx), Ok(raw)) => {
                *res = render_error(&ctx, req.headers(), raw, self.0).await;
            }
            _ => WebError(self.0).write(req, depot, res).await,
        }
    }
}

pub(super) fn flow_response(
    flow: FlowDecision,
    ctx: &AppState,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    Ok(match flow {
        FlowDecision::LoginRequired { login_id } => login_redirect(ctx, &login_id)?,
        FlowDecision::Continue { login_id } => {
            redirect_to_response(&format!("/oauth2/continue?login_id={login_id}"))
        }
        FlowDecision::OAuthError { request, error } => {
            redirect_oauth_error_response(ctx, headers, &request, error)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use http::{HeaderMap, HeaderValue, StatusCode, header};
    use identity_application::error::{AppError, codes::authorize::AuthorizeErrorCode};
    use identity_domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, ResponseMode, ResponseType, ScopeSet,
    };
    use identity_infrastructure::test_app_state_with_mock_settings;
    use salvo::test::ResponseExt;
    use url::Url;
    use uuid::Uuid;

    use super::{
        finish_authorize_redirect, form_post_action_and_fields, inline_script_csp_header_value,
        localized_authorize_error_response, redirect_oauth_error_response,
    };

    #[tokio::test]
    async fn localized_scope_error_redirect_preserves_unassigned_scope() {
        let ctx = test_app_state_with_mock_settings().await;
        let error = AppError::from_code(AuthorizeErrorCode::ScopeNotAssignedToClient)
            .with_param("scopes", "email");
        let redirect_uri = Url::parse("https://client.example.com/callback").unwrap();

        for (language, expected) in [
            ("zh-CN", "客户端无权请求 scope：email"),
            (
                "en-US",
                "The client is not allowed to request scope(s): email.",
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::ACCEPT_LANGUAGE,
                HeaderValue::from_str(language).unwrap(),
            );
            let response = localized_authorize_error_response(&ctx, &headers, &error)
                .with_state("state123")
                .with_issuer("https://identity.example.com/");
            let redirect = response.to_redirect_url(&redirect_uri);
            let params = redirect.query_pairs().collect::<HashMap<_, _>>();

            assert_eq!(params.len(), 4);
            assert_eq!(
                params.get("error").map(AsRef::as_ref),
                Some("invalid_scope")
            );
            assert_eq!(
                params.get("error_description").map(AsRef::as_ref),
                Some(expected)
            );
            assert_eq!(params.get("state").map(AsRef::as_ref), Some("state123"));
            assert_eq!(
                params.get("iss").map(AsRef::as_ref),
                Some("https://identity.example.com/")
            );
        }
    }

    #[tokio::test]
    async fn form_post_error_uses_autopost_template() {
        let ctx = test_app_state_with_mock_settings().await;
        let headers = HeaderMap::new();
        let request = AuthorizationRequest {
            resources: Vec::new(),
            response_type: ResponseType::Code,
            response_mode: Some(ResponseMode::FormPost),
            client_id: Uuid::nil(),
            redirect_uri: Url::parse("https://client.example.com/callback").unwrap(),
            redirect_uri_raw: "https://client.example.com/callback".to_owned(),
            redirect_uri_was_supplied: true,
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

        let mut response =
            redirect_oauth_error_response(&ctx, &headers, &request, OAuthErrorCode::LoginRequired);
        let body = response.take_string().await.unwrap();

        assert!(body.contains("method=\"post\""), "{body}");
        assert!(
            body.contains("action=\"https://client.example.com/callback\""),
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
            Url::parse("https://client.example.com/callback?code=abc&state=xyz").unwrap();

        let (action, fields) = form_post_action_and_fields(&redirect_uri);

        assert_eq!(action, "https://client.example.com/callback");
        assert_eq!(fields[0].name, "code");
        assert_eq!(fields[0].value, "abc");
        assert_eq!(fields[1].name, "state");
        assert_eq!(fields[1].value, "xyz");
    }

    #[tokio::test]
    async fn finish_authorize_redirect_renders_form_post_page() {
        let ctx = test_app_state_with_mock_settings().await;
        let headers = HeaderMap::new();
        let redirect_uri =
            Url::parse("https://client.example.com/callback#code=abc&state=xyz").unwrap();

        let response =
            finish_authorize_redirect(&ctx, &headers, &redirect_uri, Some(ResponseMode::FormPost));

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }

    #[tokio::test]
    async fn finish_authorize_redirect_uses_http_redirect_for_non_form_post() {
        let ctx = test_app_state_with_mock_settings().await;
        let headers = HeaderMap::new();
        let redirect_uri =
            Url::parse("https://client.example.com/callback?code=abc&state=xyz").unwrap();

        let response = finish_authorize_redirect(&ctx, &headers, &redirect_uri, None);

        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    }

    #[test]
    fn inline_script_csp_header_value_allows_inline_scripts() {
        let nonce = "test-nonce-123";
        assert_eq!(
            inline_script_csp_header_value(nonce),
            HeaderValue::from_static("default-src 'self'; script-src 'nonce-test-nonce-123'")
        );
    }
}
