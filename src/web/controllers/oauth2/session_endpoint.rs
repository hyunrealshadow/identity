use http::{StatusCode, header};
use salvo::{Depot, Request, Response, handler};

use crate::controllers::{
    response::{app_state, render_html},
    shared::load_active_session_entries,
};

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
    let body = format!(
        r#"<!doctype html><title>OP session iframe</title><script>
const opBrowserState = {op_browser_state:?};
function base64url(bytes) {{
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}}
async function calculateSessionState(clientId, origin, sessionState) {{
  const dot = sessionState.lastIndexOf(".");
  if (dot < 1 || dot === sessionState.length - 1) return null;
  const salt = sessionState.slice(dot + 1);
  const data = new TextEncoder().encode(`${{clientId}} ${{origin}} ${{opBrowserState}} ${{salt}}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return `${{base64url(digest)}}.${{salt}}`;
}}
window.addEventListener("message", async (event) => {{
  const parts = String(event.data || "").split(" ");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {{
    event.source && event.source.postMessage("error", event.origin);
    return;
  }}
  const expected = await calculateSessionState(parts[0], event.origin, parts[1]);
  if (expected === null) {{
    event.source && event.source.postMessage("error", event.origin);
    return;
  }}
  event.source && event.source.postMessage(expected === parts[1] ? "unchanged" : "changed", event.origin);
}});
</script>"#
    );

    render_html(res, StatusCode::OK, body);
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
