use http::HeaderMap;
use salvo::{Depot, Request, Response, handler};

use crate::application::error::AppError;
use crate::boot::AppState;
use crate::domain::openid_connect::{OAuthErrorCode, OAuthErrorResponse, ResponseType};
use crate::web::controllers::response::AppResponse;

use super::{
    super::shared::load_active_sessions,
    authorize_extractor::{authorize_input_error, extract_authorize_request},
    authorize_interaction::determine_authorize_flow,
    authorize_response::render_authorize_error_page,
};

fn render_error(
    ctx: &AppState,
    headers: &HeaderMap,
    raw: &super::authorize_extractor::RawAuthorizeRequest,
    error: AppError,
) -> Response {
    tracing::warn!(error_code = error.code(), error = %error, "authorize validation error");
    // Non-redirectable error codes (client/redirect_uri issues)
    const NON_REDIRECTABLE: &[u32] = &[23000, 23001, 23002, 23004, 23014];

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
                let error_response = match raw
                    .response_type
                    .as_deref()
                    .and_then(|value| value.parse::<ResponseType>().ok())
                {
                    Some(response_type) if response_type.is_implicit() => {
                        error_response.to_fragment_redirect_url(&uri)
                    }
                    _ => error_response.to_redirect_url(&uri),
                };
                return crate::web::controllers::response::redirect_to_response(
                    error_response.as_str(),
                );
            }
        }
    }

    render_authorize_error_page(ctx, headers, raw, error)
}

#[handler]
pub async fn authorize(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = crate::web::controllers::response::app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let authorize_request = extract_authorize_request(req).await?;
    if let Some(error) = authorize_input_error(&authorize_request.raw) {
        return Ok(
            render_authorize_error_page(&ctx, &headers, &authorize_request.raw, error).into(),
        );
    }

    let authorize_service = ctx.services().oidc_authorize();
    let raw_request = authorize_request.raw.clone();

    let (request, client) = match authorize_service
        .validate_request(authorize_request.raw.into())
        .await
    {
        Ok(value) => value,
        Err(error) => return Ok(render_error(&ctx, &headers, &raw_request, error).into()),
    };

    let active_sessions = match load_active_sessions(&ctx, &headers).await {
        Ok(value) => value,
        Err(error) => return Ok(render_error(&ctx, &headers, &raw_request, error).into()),
    };
    let authorization_request_id = match authorize_service
        .create_authorization_request(&request)
        .await
    {
        Ok(value) => value,
        Err(error) => return Ok(render_error(&ctx, &headers, &raw_request, error).into()),
    };
    let login_id = match authorize_service
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
    {
        Ok(value) => value,
        Err(error) => return Ok(render_error(&ctx, &headers, &raw_request, error).into()),
    };

    let flow = match determine_authorize_flow(
        &request,
        &client,
        &active_sessions,
        authorization_request_id,
        login_id,
        authorize_service,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return Ok(render_error(&ctx, &headers, &raw_request, error).into()),
    };

    Ok(flow.into_response().into())
}

#[cfg(test)]
mod tests {
    use crate::domain::openid_connect::{
        AuthorizationRequest, OAuthErrorCode, PromptValue, ResponseType, ScopeSet,
    };
    use http::{StatusCode, header};
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };
    use std::collections::HashSet;

    async fn response_body_text(mut response: salvo::Response) -> String {
        response.take_string().await.unwrap()
    }

    async fn call_authorize(uri: &str) -> salvo::Response {
        let app = super::super::routes().hoop(salvo::affix_state::inject(
            crate::boot::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        TestClient::get(format!("http://127.0.0.1:5800{uri}"))
            .send(&service)
            .await
    }

    #[tokio::test]
    async fn authorize_routes_accept_post_requests() {
        let app = super::super::routes().hoop(salvo::affix_state::inject(
            crate::boot::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::post("http://127.0.0.1:5800/oauth2/authorize")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .send(&service)
            .await;

        assert_ne!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
    }

    #[tokio::test]
    async fn authorize_renders_html_error_page_for_missing_required_fields() {
        let response = call_authorize("/oauth2/authorize?scope=openid").await;

        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
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

        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
        let location = response.headers().get(header::LOCATION).unwrap();
        assert!(location.to_str().unwrap().contains("error=login_required"));
    }

    #[tokio::test]
    async fn authorize_redirects_implicit_oauth_error_in_fragment() {
        let request = AuthorizationRequest {
            response_type: ResponseType::IdToken,
            client_id: uuid::Uuid::nil(),
            redirect_uri: url::Url::parse("https://client.example.com/callback").unwrap(),
            scope: ScopeSet::parse("openid").unwrap(),
            state: "state".to_string(),
            nonce: Some("nonce".to_string()),
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

        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
        let location = response.headers().get(header::LOCATION).unwrap();
        let location = url::Url::parse(location.to_str().unwrap()).unwrap();
        assert_eq!(location.query(), None);
        assert_eq!(
            location.fragment(),
            Some("error=login_required&state=state")
        );
    }
}
