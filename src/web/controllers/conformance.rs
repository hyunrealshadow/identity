//! Conformance test automation endpoints.
//!
//! These routes are **only mounted when `APP_ENV=conformance`** and must never
//! be reachable in production.
//!
//! Routes:
//!   POST /conformance/auto-login  – complete a full login+consent in one call

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::auth::login::ChallengeOutcome,
    boot::AppState,
    web::controllers::shared::{build_selected_session_cookie, build_session_context, is_secure_cookie},
};

use super::response::AppJson;

pub fn routes() -> Router<AppState> {
    Router::new().route("/conformance/auto-login", post(auto_login))
}

#[derive(Debug, Deserialize)]
struct AutoLoginRequest {
    login_id: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AutoLoginResponse {
    redirect_uri: String,
}

#[derive(Debug, Serialize)]
struct AutoLoginError {
    error: String,
}

#[axum::debug_handler]
async fn auto_login(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<AutoLoginRequest>,
) -> Response {
    // Step 1: decrypt login_id → login_oid
    let login_oid = match ctx
        .services()
        .oidc_authorize()
        .decrypt_login_id(&body.login_id)
        .await
    {
        Ok(oid) => oid,
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: decrypt_login_id failed");
            return (
                StatusCode::BAD_REQUEST,
                AppJson(AutoLoginError {
                    error: "invalid_login_id".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Step 2: identify
    let identify_result = match ctx
        .services()
        .login()
        .identify(login_oid, &body.username)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: identify failed");
            return (
                StatusCode::BAD_REQUEST,
                AppJson(AutoLoginError {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    // Step 3: password challenge
    let sess_ctx = build_session_context(&headers);
    let session = match ctx
        .services()
        .login()
        .challenge(login_oid, "password", &body.password, sess_ctx)
        .await
    {
        Ok(ChallengeOutcome::Authenticated { session, .. }) => session,
        Ok(ChallengeOutcome::MfaRequired { .. }) => {
            return (
                StatusCode::BAD_REQUEST,
                AppJson(AutoLoginError {
                    error: "mfa_required".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: challenge failed");
            return (
                StatusCode::UNAUTHORIZED,
                AppJson(AutoLoginError {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    // Step 4: approve authorization request
    let redirect_uri = match ctx
        .services()
        .oidc_authorize()
        .approve_authorization_request_by_login(
            &body.login_id,
            session.oid,
            identify_result.user.oid.into(),
            Some(session.created_at.timestamp()),
        )
        .await
    {
        Ok(url) => url,
        Err(e) => {
            tracing::error!(error = %e, "auto_login: approve failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AppJson(AutoLoginError {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    // Step 5: build session cookie and return redirect_uri
    let cookie = build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));

    (
        [(header::SET_COOKIE, cookie)],
        AppJson(AutoLoginResponse {
            redirect_uri: redirect_uri.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn auto_login_returns_bad_request_for_invalid_login_id() {
        let app = super::routes()
            .with_state(crate::boot::test_app_state_with_mock_settings().await);

        let request = Request::builder()
            .method(Method::POST)
            .uri("/conformance/auto-login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"login_id":"invalid","username":"test@example.com","password":"wrong"}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // The mock DB cannot decrypt the login_id, so we expect 400.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
