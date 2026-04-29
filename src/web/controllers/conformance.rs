//! Conformance test automation endpoints.
//!
//! These routes are **only mounted when `APP_ENV=conformance`** and must never
//! be reachable in production.
//!
//! Routes:
//!   POST /conformance/auto-login  – complete a full login+consent in one call

use http::{HeaderMap, StatusCode};
use salvo::{Depot, Request, Response, Router, handler};
use serde::{Deserialize, Serialize};

use crate::{
    application::auth::login::ChallengeOutcome,
    web::controllers::shared::{
        build_selected_session_cookie, build_session_context, is_secure_cookie,
    },
};

use super::response::{app_state, parse_json, render_json};

pub fn routes() -> Router {
    Router::with_path("conformance/auto-login").post(auto_login)
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

#[handler]
async fn auto_login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), identity_application::error::AppError> {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let body: AutoLoginRequest = parse_json(req).await?;
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
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                AutoLoginError {
                    error: "invalid_login_id".to_string(),
                },
            );
            return Ok(());
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
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                AutoLoginError {
                    error: e.to_string(),
                },
            );
            return Ok(());
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
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                AutoLoginError {
                    error: "mfa_required".to_string(),
                },
            );
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "auto_login: challenge failed");
            render_json(
                res,
                StatusCode::UNAUTHORIZED,
                AutoLoginError {
                    error: e.to_string(),
                },
            );
            return Ok(());
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
            render_json(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                AutoLoginError {
                    error: e.to_string(),
                },
            );
            return Ok(());
        }
    };

    // Step 5: build session cookie and return redirect_uri
    let cookie = build_selected_session_cookie(&headers, session.oid, is_secure_cookie(&ctx));

    render_json(
        res,
        StatusCode::OK,
        AutoLoginResponse {
            redirect_uri: redirect_uri.to_string(),
        },
    );
    super::shared::append_set_cookie(res, &cookie);
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use salvo::{Service, test::TestClient};

    #[tokio::test]
    async fn auto_login_returns_bad_request_for_invalid_login_id() {
        let app = super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::post("http://127.0.0.1:5800/conformance/auto-login")
            .raw_json(r#"{"login_id":"invalid","username":"test@example.com","password":"wrong"}"#)
            .send(&service)
            .await;

        // The mock DB cannot decrypt the login_id, so we expect 400.
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }
}
