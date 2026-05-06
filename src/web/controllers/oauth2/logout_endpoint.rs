use http::StatusCode;
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;
use uuid::Uuid;

use identity_application::openid_connect::logout::{LogoutOutcome, RpInitiatedLogoutRequest};

use crate::controllers::response::render_html;
use crate::controllers::{
    response::{AppResponse, app_state, parse_form, parse_query, redirect_to_response},
    shared::{
        append_set_cookie, build_session_cookie, is_secure_cookie, load_active_sessions,
        parse_session_cookie,
    },
};

#[derive(Debug, Deserialize)]
struct LogoutParams {
    id_token_hint: Option<String>,
    logout_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    ui_locales: Option<String>,
}

impl From<LogoutParams> for RpInitiatedLogoutRequest {
    fn from(value: LogoutParams) -> Self {
        Self {
            id_token_hint: value.id_token_hint,
            logout_hint: value.logout_hint,
            client_id: value.client_id,
            post_logout_redirect_uri: value.post_logout_redirect_uri,
            state: value.state,
            ui_locales: value.ui_locales,
        }
    }
}

pub fn session_cookie_without(oids: &[Uuid], revoked: Uuid, secure: bool) -> String {
    let remaining = oids
        .iter()
        .copied()
        .filter(|oid| *oid != revoked)
        .collect::<Vec<_>>();
    build_session_cookie(&remaining, secure)
}

pub fn redirect_or_page_response(outcome: LogoutOutcome, set_cookie: Option<String>) -> Response {
    let mut response = match outcome {
        LogoutOutcome::Redirect { redirect_uri } => redirect_to_response(redirect_uri.as_str()),
        LogoutOutcome::LoggedOut => {
            let mut response = Response::new();
            render_html(
                &mut response,
                StatusCode::OK,
                "<!doctype html><title>Signed out</title><h1>Signed out</h1>".to_owned(),
            );
            response
        }
    };

    if let Some(cookie) = set_cookie {
        append_set_cookie(&mut response, &cookie);
    }

    response
}

async fn handle_logout(
    depot: &mut Depot,
    req: &mut Request,
    params: LogoutParams,
) -> Result<AppResponse, identity_application::error::AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let session_oids = parse_session_cookie(&headers);
    let session_to_revoke = load_active_sessions(&ctx, &headers)
        .await?
        .first()
        .map(|session| session.session_oid);

    let outcome = ctx
        .services()
        .oidc_logout()
        .rp_initiated_logout(params.into())
        .await?;

    let set_cookie = if let Some(session_oid) = session_to_revoke {
        let _ = ctx.services().session().revoke(session_oid).await;
        Some(session_cookie_without(
            &session_oids,
            session_oid,
            is_secure_cookie(&ctx),
        ))
    } else {
        None
    };

    Ok(redirect_or_page_response(outcome, set_cookie).into())
}

#[handler]
pub async fn logout_get(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, identity_application::error::AppError> {
    let params: LogoutParams = parse_query(req)?;
    handle_logout(depot, req, params).await
}

#[handler]
pub async fn logout_post(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, identity_application::error::AppError> {
    let params: LogoutParams = parse_form(req).await?;
    handle_logout(depot, req, params).await
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use salvo::{Service, test::TestClient};

    #[test]
    fn remove_session_cookie_entry_keeps_other_sessions() {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();

        let cookie = super::session_cookie_without(&[first, second], first, false);

        assert!(!cookie.contains(&first.to_string()));
        assert!(cookie.contains(&second.to_string()));
    }

    #[tokio::test]
    async fn logout_route_renders_logged_out_page_without_redirect() {
        let app = super::super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::get("http://127.0.0.1:5800/oauth2/logout")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }

    #[test]
    fn redirect_response_preserves_set_cookie_header() {
        let response = super::redirect_or_page_response(
            identity_application::openid_connect::logout::LogoutOutcome::Redirect {
                redirect_uri: url::Url::parse("https://rp.example.com/logout?state=abc").unwrap(),
            },
            Some("sessions=[]; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600".to_owned()),
        );

        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://rp.example.com/logout?state=abc"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_some());
    }
}
