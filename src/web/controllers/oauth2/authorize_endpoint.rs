use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};

use crate::application::error::AppError;
use crate::boot::AppState;
use crate::domain::openid_connect::{OAuthErrorCode, OAuthErrorResponse};

use super::{
    super::shared::load_active_sessions,
    authorize_extractor::{AuthorizeRequestExtractor, authorize_input_error},
    authorize_interaction::determine_authorize_flow,
    authorize_response::render_authorize_error_page,
};

pub enum AuthorizeError {
    RenderPage(Response),
}

impl IntoResponse for AuthorizeError {
    fn into_response(self) -> Response {
        match self {
            AuthorizeError::RenderPage(response) => response,
        }
    }
}

fn render_error(
    ctx: &AppState,
    headers: &HeaderMap,
    raw: &super::authorize_extractor::RawAuthorizeRequest,
    error: AppError,
) -> AuthorizeError {
    tracing::warn!(error_code = error.code(), error = %error, "authorize validation error");
    // Non-redirectable error codes (client/redirect_uri issues)
    const NON_REDIRECTABLE: &[u32] = &[6000, 6001, 6002, 6004, 6014];

    let can_redirect = !NON_REDIRECTABLE.contains(&error.code())
        && raw.redirect_uri.as_deref().is_some_and(|u| !u.is_empty())
        && raw.client_id.as_deref().is_some_and(|c| !c.is_empty());

    if can_redirect {
        if let Some(redirect_uri) = raw.redirect_uri.as_deref() {
            if let Ok(uri) = url::Url::parse(redirect_uri) {
                let error_response = OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest);
                let error_response = if let Some(s) = raw.state.clone() {
                    error_response.with_state(s)
                } else {
                    error_response
                };
                let error_response = error_response.to_redirect_url(&uri);
                return AuthorizeError::RenderPage(
                    Redirect::to(error_response.as_str()).into_response(),
                );
            }
        }
    }

    AuthorizeError::RenderPage(render_authorize_error_page(ctx, headers, raw, error))
}

#[axum::debug_handler]
pub async fn authorize(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    authorize_request: AuthorizeRequestExtractor,
) -> Result<Response, AuthorizeError> {
    if let Some(error) = authorize_input_error(&authorize_request.raw) {
        return Ok(render_authorize_error_page(
            &ctx,
            &headers,
            &authorize_request.raw,
            error,
        ));
    }

    let authorize_service = ctx.services().oidc_authorize();
    let raw_request = authorize_request.raw.clone();

    let (request, client) = authorize_service
        .validate_request(authorize_request.raw.into())
        .await
        .map_err(|error| render_error(&ctx, &headers, &raw_request, error))?;

    let active_sessions = load_active_sessions(&ctx, &headers)
        .await
        .map_err(|e| render_error(&ctx, &headers, &raw_request, e))?;
    let authorization_request_id = authorize_service
        .create_authorization_request(&request)
        .await
        .map_err(|e| render_error(&ctx, &headers, &raw_request, e))?;
    let login_id = authorize_service
        .create_login_flow(
            request.client_id,
            authorization_request_id,
            request
                .acr_values
                .as_ref()
                .and_then(|values| values.first())
                .map(String::as_str),
        )
        .await
        .map_err(|e| render_error(&ctx, &headers, &raw_request, e))?;

    let flow = determine_authorize_flow(
        &request,
        &client,
        &active_sessions,
        authorization_request_id,
        login_id,
        authorize_service,
    )
    .await
    .map_err(|e| render_error(&ctx, &headers, &raw_request, e))?;

    Ok(flow.into_response())
}

#[cfg(test)]
mod tests {
    use crate::domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, PromptValue, ResponseType, ScopeSet,
    };
    use axum::body::to_bytes;
    use std::collections::HashSet;
    use tower::util::ServiceExt;

    async fn response_body_text(response: axum::response::Response) -> String {
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    async fn call_authorize(uri: &str) -> axum::response::Response {
        let app = super::super::routes()
            .with_state(crate::boot::test_app_state_with_mock_settings().await);
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();

        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn authorize_routes_accept_post_requests() {
        let app = super::super::routes()
            .with_state(crate::boot::test_app_state_with_mock_settings().await);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/oauth2/authorize")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_ne!(
            response.status(),
            axum::http::StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[tokio::test]
    async fn authorize_renders_html_error_page_for_missing_required_fields() {
        let response = call_authorize("/oauth2/authorize?scope=openid").await;

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = response_body_text(response).await;
        assert!(body.contains("Authorization request is invalid"), "{body}");
        assert!(
            body.contains("missing required parameter: client_id"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn authorize_redirects_oauth_error_after_redirect_uri_validation() {
        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: uuid::Uuid::nil(),
            redirect_uri: url::Url::parse("https://client.example.com/callback").unwrap(),
            scope: ScopeSet::parse("openid").unwrap(),
            state: "state".to_string(),
            nonce: None,
            display: None,
            prompt: Some(HashSet::from([PromptValue::None])),
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

        let response = super::super::authorize_response::redirect_oauth_error_response(
            &request,
            OAuthErrorCode::LoginRequired,
        );

        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap();
        assert!(location.to_str().unwrap().contains("error=login_required"));
    }
}
