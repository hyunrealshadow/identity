use http::{HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;
use uuid::Uuid;

use identity_application::openid_connect::logout::{
    FrontChannelLogoutNotification, LogoutOutcome, RpInitiatedLogoutRequest,
};

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
            session_oid: None,
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
        LogoutOutcome::FrontChannel {
            notifications,
            post_logout_redirect_uri,
        } => {
            let mut response = Response::new();
            render_html(
                &mut response,
                StatusCode::OK,
                frontchannel_logout_html(&notifications, post_logout_redirect_uri.as_ref()),
            );
            response.headers_mut().insert(
                header::HeaderName::from_static("content-security-policy"),
                frontchannel_logout_content_security_policy(&notifications),
            );
            response
        }
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

fn frontchannel_logout_html(
    notifications: &[FrontChannelLogoutNotification],
    post_logout_redirect_uri: Option<&url::Url>,
) -> String {
    let frames = notifications
        .iter()
        .map(|notification| {
            format!(
                r#"<iframe src="{}" title="front-channel logout" hidden></iframe>"#,
                escape_html_attribute(notification.logout_uri.as_str())
            )
        })
        .collect::<String>();

    let redirect_script = post_logout_redirect_uri
        .map(|uri| {
            format!(
                r#"<script>setTimeout(function(){{window.location.href="{}";}}, 300);</script>"#,
                escape_js_string(uri.as_str())
            )
        })
        .unwrap_or_default();

    format!("<!doctype html><title>Signed out</title><h1>Signed out</h1>{frames}{redirect_script}")
}

fn frontchannel_logout_content_security_policy(
    notifications: &[FrontChannelLogoutNotification],
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
        "default-src 'none'; frame-src {frame_src}; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
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

fn escape_html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
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

    let mut request: RpInitiatedLogoutRequest = params.into();
    request.session_oid = session_to_revoke;

    let outcome = ctx
        .services()
        .oidc_logout()
        .rp_initiated_logout(request)
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

    #[test]
    fn frontchannel_logout_html_renders_iframes_before_redirect_script() {
        let html = super::frontchannel_logout_html(
            &[identity_application::openid_connect::logout::FrontChannelLogoutNotification {
                client_id: uuid::Uuid::new_v4(),
                logout_uri: url::Url::parse(
                    "https://rp.example.com/frontchannel_logout?iss=https%3A%2F%2Fidentity.example.com%2F&sid=session-1",
                )
                .unwrap(),
            }],
            Some(&url::Url::parse("https://rp.example.com/post_logout").unwrap()),
        );

        let iframe_position = html.find("<iframe").unwrap();
        let redirect_position = html.find("window.location.href").unwrap();

        assert!(html.contains("https://rp.example.com/frontchannel_logout"));
        assert!(html.contains("sid=session-1"));
        assert!(iframe_position < redirect_position);
    }

    #[test]
    fn frontchannel_logout_response_allows_frontchannel_frames_and_redirect_script() {
        let response = super::redirect_or_page_response(
            identity_application::openid_connect::logout::LogoutOutcome::FrontChannel {
                notifications: vec![identity_application::openid_connect::logout::FrontChannelLogoutNotification {
                    client_id: uuid::Uuid::new_v4(),
                    logout_uri: url::Url::parse(
                        "https://localhost.emobix.co.uk:8443/test/a/identity-frontchannel/frontchannel_logout",
                    )
                    .unwrap(),
                }],
                post_logout_redirect_uri: Some(
                    url::Url::parse(
                        "https://localhost.emobix.co.uk:8443/test/a/identity-session/post_logout_redirect",
                    )
                    .unwrap(),
                ),
            },
            None,
        );

        let csp = response
            .headers()
            .get(header::HeaderName::from_static("content-security-policy"))
            .unwrap()
            .to_str()
            .unwrap();

        assert!(csp.contains("frame-src https://localhost.emobix.co.uk:8443"));
        assert!(csp.contains("script-src 'unsafe-inline'"));
    }
}
