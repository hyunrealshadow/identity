use http::{StatusCode, header};
use identity_infrastructure::web::tera::render_view;
use salvo::{Depot, Request, Response, handler, handler::HoopedHandler};
use serde_json::to_string;

use super::super::pipeline::{Endpoint, RequireState, take};
use crate::{
    controllers::{
        response::{WebError, WebResult, app_state, render_app_error, render_html},
        shared::{
            generate_csp_nonce, inline_script_csp_header_value, load_op_active_session_entries,
        },
    },
    views::oauth2::CheckSessionPageData,
};

struct BrowserState {
    nonce: String,
    value: String,
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("check_session")
        .action("state", RequireState::<WebError>::new())
        .action("load_browser_state", load_browser_state)
        .finish("render_iframe", check_session_iframe)
}

#[handler]
async fn load_browser_state(depot: &mut Depot, req: &mut Request) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let nonce = generate_csp_nonce();
    let entries = load_op_active_session_entries(&ctx, req.headers()).await?;
    let value = entries
        .iter()
        .map(|entry| entry.protected_session_id.as_str())
        .collect::<Vec<_>>()
        .join(".");
    depot.insert_typed(BrowserState { nonce, value });
    Ok(())
}

#[handler]
async fn check_session_iframe(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let BrowserState {
        nonce,
        value: op_browser_state,
    } = take(depot)?;

    let data = CheckSessionPageData {
        op_browser_state_json: to_string(&op_browser_state).unwrap_or_else(|_| "\"\"".to_owned()),
        lang: "en".to_owned(),
        nonce: nonce.clone(),
    };

    match render_view(&ctx, req.headers(), "oauth2/check_session.html", data) {
        Ok(body) => render_html(res, StatusCode::OK, body),
        Err(error) => render_app_error(res, req.headers(), &ctx, error),
    }

    res.headers_mut().insert(
        header::HeaderName::from_static("content-security-policy"),
        inline_script_csp_header_value(&nonce),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use identity_infrastructure::test_app_state_with_mock_settings;
    use salvo::{
        Service,
        affix_state::inject,
        test::{ResponseExt, TestClient},
    };

    use crate::controllers::oauth2::routes;

    #[tokio::test]
    async fn check_session_iframe_renders_post_message_script() {
        let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
        let service = Service::new(app);

        let mut response = TestClient::get("http://127.0.0.1:5800/oauth2/check_session")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(
            response
                .headers()
                .get(header::HeaderName::from_static("content-security-policy"))
                .and_then(|value| value.to_str().ok())
                .is_some_and(|v| v.contains("script-src 'nonce-")),
            "CSP header should use nonce-based script-src"
        );
        let body = response.take_string().await.unwrap();
        assert!(
            body.contains("window.addEventListener(\"message\""),
            "{body}"
        );
        assert!(body.contains("postMessage"), "{body}");
        assert!(body.contains("opBrowserState"), "{body}");
        assert!(body.contains("\"unchanged\""), "{body}");
        assert!(body.contains("\"changed\""), "{body}");
    }
}
