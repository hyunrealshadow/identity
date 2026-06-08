use http::{StatusCode, header};
use salvo::{Depot, Request, Response, handler};

use crate::{
    controllers::{
        response::{WebResult, app_state, render_app_error, render_html},
        shared::{generate_csp_nonce, load_active_session_entries},
    },
    views::oauth2::CheckSessionPageData,
};

#[handler]
pub async fn check_session_iframe(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let nonce = generate_csp_nonce();
    let active_sessions = load_active_session_entries(&ctx, req.headers()).await?;
    let op_browser_state = active_sessions
        .iter()
        .map(|entry| entry.protected_session_id.as_str())
        .collect::<Vec<_>>()
        .join(".");

    let data = CheckSessionPageData {
        op_browser_state,
        lang: "en".to_owned(),
        nonce: nonce.clone(),
    };

    match identity_infrastructure::web::tera::render_view(
        &ctx,
        req.headers(),
        "oauth2/check_session.html",
        data,
    ) {
        Ok(body) => render_html(res, StatusCode::OK, body),
        Err(error) => render_app_error(res, error),
    }

    res.headers_mut().insert(
        header::HeaderName::from_static("content-security-policy"),
        super::inline_script_csp_header_value(&nonce),
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
        let app = crate::controllers::oauth2::routes().hoop(salvo::affix_state::inject(
            identity_infrastructure::test_app_state_with_mock_settings().await,
        ));
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
