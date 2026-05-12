use http::{StatusCode, header};
use salvo::{Depot, Request, Response, handler};
use serde::Serialize;

use crate::controllers::{
    response::{app_state, render_html},
    shared::load_active_session_entries,
};

#[derive(Debug, Serialize)]
struct CheckSessionPageData {
    op_browser_state: String,
    lang: String,
}

#[handler]
pub async fn check_session_iframe(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), identity_application::error::AppError> {
    let ctx = app_state(depot)?;
    let active_sessions = load_active_session_entries(&ctx, req.headers()).await?;
    let op_browser_state = active_sessions
        .iter()
        .map(|entry| entry.protected_session_id.as_str())
        .collect::<Vec<_>>()
        .join(".");

    let data = CheckSessionPageData {
        op_browser_state,
        lang: "en".to_owned(),
    };

    match identity_infrastructure::web::tera::render_view(
        &ctx,
        req.headers(),
        "oauth2/check_session.html",
        data,
    ) {
        Ok(body) => render_html(res, StatusCode::OK, body),
        Err(_) => {
            render_html(
                res,
                StatusCode::OK,
                "<!doctype html><title>OP session iframe</title><script></script>".to_owned(),
            );
        }
    }

    res.headers_mut().insert(
        header::HeaderName::from_static("content-security-policy"),
        super::inline_script_csp_header_value(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };

    #[tokio::test]
    async fn check_session_iframe_renders_post_message_script() {
        let app = super::super::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
        let service = Service::new(app);

        let mut response = TestClient::get("http://127.0.0.1:5800/oauth2/check_session")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response
                .headers()
                .get(header::HeaderName::from_static("content-security-policy"))
                .and_then(|value| value.to_str().ok()),
            Some("default-src 'self'; script-src 'unsafe-inline'")
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
