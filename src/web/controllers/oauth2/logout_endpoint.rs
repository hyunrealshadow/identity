use http::{HeaderMap, HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;

use identity_application::openid_connect::logout::{
    FrontChannelLogoutNotification, LogoutOutcome, RpInitiatedLogoutRequest,
};
use identity_domain::auth::SessionOid;

use identity_infrastructure::AppState;
use identity_infrastructure::web::tera;

use crate::controllers::{
    response::{
        AppResponse, app_state, parse_form, parse_query, redirect_to_response, render_app_error,
        render_html,
    },
    shared::{
        append_set_cookie, build_session_cookie_from_protected_ids, generate_csp_nonce,
        is_secure_cookie, load_active_session_entries,
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
            session_oid: None,
            protected_session_id: None,
        }
    }
}

pub fn session_cookie_without(
    entries: &[crate::controllers::shared::SessionCookieEntry],
    revoked: SessionOid,
    secure: bool,
) -> String {
    let remaining = entries
        .iter()
        .filter(|entry| entry.session_oid != revoked)
        .map(|entry| entry.protected_session_id.clone())
        .collect::<Vec<_>>();
    build_session_cookie_from_protected_ids(&remaining, secure)
}

pub async fn redirect_or_page_response(
    ctx: &AppState,
    headers: &HeaderMap,
    outcome: LogoutOutcome,
    set_cookie: Option<String>,
) -> Response {
    let mut response = match outcome {
        LogoutOutcome::Redirect { redirect_uri } => redirect_to_response(redirect_uri.as_str()),
        _ => render_logout_page(ctx, headers, outcome, None).await,
    };

    if let Some(cookie) = set_cookie {
        append_set_cookie(&mut response, &cookie);
    }

    response
}

pub(super) async fn render_logout_page(
    ctx: &AppState,
    headers: &HeaderMap,
    outcome: LogoutOutcome,
    set_cookie: Option<String>,
) -> Response {
    let nonce = generate_csp_nonce();
    let (data, csp) = match outcome {
        LogoutOutcome::FrontChannel {
            notifications,
            post_logout_redirect_uri,
        } => {
            let data = crate::views::oauth2::LogoutPageData {
                title: "Signed out".to_owned(),
                frontchannel_notifications: notifications
                    .iter()
                    .map(|n| crate::views::oauth2::FrontChannelNotificationView {
                        logout_uri: n.logout_uri.to_string(),
                    })
                    .collect(),
                post_logout_redirect_uri: post_logout_redirect_uri.map(|u| u.to_string()),
                nonce: nonce.clone(),
            };
            let csp = frontchannel_logout_content_security_policy(&notifications, &nonce);
            (data, Some(csp))
        }
        LogoutOutcome::LoggedOut => (
            crate::views::oauth2::LogoutPageData {
                title: "Signed out".to_owned(),
                frontchannel_notifications: vec![],
                post_logout_redirect_uri: None,
                nonce,
            },
            None,
        ),
        LogoutOutcome::Redirect { .. } => unreachable!("call redirect_or_page_response instead"),
    };

    let mut response = Response::new();
    match tera::render_view(ctx, headers, "oauth2/logout.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, error),
    }
    if let Some(csp) = csp {
        response.headers_mut().insert(
            header::HeaderName::from_static("content-security-policy"),
            csp,
        );
    }
    if let Some(cookie) = set_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    response
}

fn frontchannel_logout_content_security_policy(
    notifications: &[FrontChannelLogoutNotification],
    nonce: &str,
) -> HeaderValue {
    let frame_sources = notifications
        .iter()
        .filter_map(|notification| csp_origin_source(&notification.logout_uri))
        .collect::<Vec<_>>();

    let frame_src = if frame_sources.is_empty() {
        "'none'".to_owned()
    } else {
        frame_sources.join(" ")
    };

    HeaderValue::from_str(&format!(
        "default-src 'none'; frame-src {frame_src}; script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'"))
}

fn csp_origin_source(uri: &url::Url) -> Option<String> {
    let host = uri.host_str()?;
    let mut origin = format!("{}://{}", uri.scheme(), host);
    if let Some(port) = uri.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Some(origin)
}

async fn handle_logout(
    depot: &mut Depot,
    req: &mut Request,
    params: LogoutParams,
) -> Result<AppResponse, identity_application::error::AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let session_entries = crate::controllers::shared::parse_session_cookie(&ctx, &headers).await;
    let active_entries = load_active_session_entries(&ctx, &headers).await?;
    let session_to_revoke = active_entries.first().map(|entry| {
        (
            entry.session.session_oid,
            entry.protected_session_id.clone(),
        )
    });

    let mut request: RpInitiatedLogoutRequest = params.into();
    request.session_oid = session_to_revoke.as_ref().map(|(oid, _)| *oid);
    request.protected_session_id = session_to_revoke.as_ref().map(|(_, id)| id.clone());

    let outcome = ctx
        .services()
        .oidc_logout()
        .rp_initiated_logout(request)
        .await?;

    let set_cookie = if let Some((session_oid, _)) = session_to_revoke {
        let _ = ctx.services().session().revoke(session_oid).await;
        Some(session_cookie_without(
            &session_entries,
            session_oid,
            is_secure_cookie(&ctx),
        ))
    } else {
        None
    };

    let response = match &outcome {
        LogoutOutcome::Redirect { .. } => {
            redirect_or_page_response(&ctx, &headers, outcome, set_cookie).await
        }
        _ => render_logout_page(&ctx, &headers, outcome, set_cookie).await,
    };

    Ok(response.into())
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
    use identity_domain::auth::SessionOid;
    use salvo::{Service, test::TestClient};

    #[test]
    fn remove_session_cookie_entry_keeps_other_sessions() {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let entries = [
            crate::controllers::shared::SessionCookieEntry {
                session_oid: SessionOid(first),
                protected_session_id: "protected-first".to_string(),
            },
            crate::controllers::shared::SessionCookieEntry {
                session_oid: SessionOid(second),
                protected_session_id: "protected-second".to_string(),
            },
        ];

        let cookie = super::session_cookie_without(&entries, SessionOid(first), false);

        assert!(!cookie.contains(&first.to_string()));
        assert!(!cookie.contains("protected-first"));
        assert!(cookie.contains("protected-second"));
    }

    #[tokio::test]
    async fn logout_route_renders_logged_out_page_without_redirect() {
        let app = crate::controllers::oauth2::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let response = TestClient::get("http://127.0.0.1:5800/oauth2/logout")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }

    #[tokio::test]
    async fn redirect_response_preserves_set_cookie_header() {
        let state = identity_infrastructure::test_app_state_with_mock_settings().await;
        let headers = http::HeaderMap::new();
        let response = super::redirect_or_page_response(
            &state,
            &headers,
            identity_application::openid_connect::logout::LogoutOutcome::Redirect {
                redirect_uri: url::Url::parse("https://rp.example.com/logout?state=abc").unwrap(),
            },
            Some("sessions=[]; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600".to_owned()),
        )
        .await;

        assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://rp.example.com/logout?state=abc"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn frontchannel_logout_sets_csp_header() {
        let state = identity_infrastructure::test_app_state_with_mock_settings().await;
        let headers = http::HeaderMap::new();
        let response = super::render_logout_page(
            &state,
            &headers,
            identity_application::openid_connect::logout::LogoutOutcome::FrontChannel {
                notifications: vec![identity_application::openid_connect::logout::FrontChannelLogoutNotification {
                    client_id: uuid::Uuid::new_v4(),
                    logout_uri: url::Url::parse(
                        "https://localhost.emobix.co.uk:8443/test/a/identity-frontchannel/frontchannel_logout",
                    )
                    .unwrap(),
                }],
                post_logout_redirect_uri: None,
            },
            None,
        )
        .await;

        let csp = response
            .headers()
            .get(header::HeaderName::from_static("content-security-policy"))
            .unwrap()
            .to_str()
            .unwrap();

        assert!(csp.contains("frame-src https://localhost.emobix.co.uk:8443"));
        assert!(csp.contains("script-src 'nonce-"));
    }

    #[tokio::test]
    async fn frontchannel_logout_renders_title() {
        let state = identity_infrastructure::test_app_state_with_mock_settings().await;
        let headers = http::HeaderMap::new();
        let response = super::render_logout_page(
            &state,
            &headers,
            identity_application::openid_connect::logout::LogoutOutcome::LoggedOut,
            None,
        )
        .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
    }
}
