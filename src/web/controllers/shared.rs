//! Shared helpers used by both the JSON API (`auth`) and the SSR UI (`auth_ui`)
//! controllers. Keeping them here avoids duplication and ensures both surfaces
//! behave identically for cookie handling, etc.

use axum::{
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use rand::RngCore;
use uuid::Uuid;

use crate::{
    application::{
        auth::login::SessionContext,
        error::{AppError, codes::common::CommonErrorCode},
    },
    boot::AppState,
    domain::auth::model::ActiveSession,
    domain::auth::{SESSION_COOKIE_NAME, SESSION_EXPIRY},
};

pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";
pub const CSRF_FORM_FIELD_NAME: &str = "csrf_token";

fn parse_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|cookie| {
            let (name, value) = cookie.split_once('=')?;
            if name.trim() == cookie_name {
                Some(value.trim().to_owned())
            } else {
                None
            }
        })
}

/// Parse the `sessions` cookie from request headers.
///
/// The cookie value is a JSON array of UUID strings.  Returns an empty `Vec`
/// when the cookie is absent or malformed.
pub fn parse_session_cookie(headers: &HeaderMap) -> Vec<Uuid> {
    parse_cookie(headers, SESSION_COOKIE_NAME)
        .and_then(|raw| serde_json::from_str::<Vec<Uuid>>(&raw).ok())
        .unwrap_or_default()
}

pub fn parse_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    parse_cookie(headers, CSRF_COOKIE_NAME).filter(|token| !token.is_empty())
}

/// Build the `Set-Cookie` header value for the sessions cookie.
///
/// Set `secure = true` in production so the cookie is only sent over HTTPS.
pub fn build_session_cookie(oids: &[Uuid], secure: bool) -> String {
    let json = serde_json::to_string(oids).unwrap_or_else(|_| "[]".to_owned());
    let max_age = SESSION_EXPIRY.as_secs();
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}={json}; HttpOnly{secure_flag}; SameSite=Lax; Path=/; Max-Age={max_age}"
    )
}

pub fn build_selected_session_cookie(
    headers: &HeaderMap,
    session_oid: Uuid,
    secure: bool,
) -> String {
    let mut oids = parse_session_cookie(headers);
    oids.retain(|oid| *oid != session_oid);
    oids.insert(0, session_oid);
    build_session_cookie(&oids, secure)
}

pub async fn load_active_sessions(
    ctx: &AppState,
    headers: &HeaderMap,
) -> Result<Vec<ActiveSession>, AppError> {
    let session_oids = parse_session_cookie(headers);

    if session_oids.is_empty() {
        return Ok(Vec::new());
    }

    ctx.services()
        .session()
        .get_active_accounts(&session_oids)
        .await
}

/// Return `true` when the app is running in the `production` environment,
/// which triggers the `Secure` flag on session cookies.
pub fn is_secure_cookie(ctx: &AppState) -> bool {
    ctx.context().is_production()
}

pub fn build_csrf_cookie(token: &str, secure: bool) -> String {
    let max_age = SESSION_EXPIRY.as_secs();
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{CSRF_COOKIE_NAME}={token};{secure_flag} SameSite=Lax; Path=/; Max-Age={max_age}")
}

pub fn ensure_csrf_token(headers: &HeaderMap, secure: bool) -> (String, Option<String>) {
    if let Some(token) = parse_csrf_cookie(headers) {
        return (token, None);
    }

    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let cookie = build_csrf_cookie(&token, secure);
    (token, Some(cookie))
}

pub fn append_set_cookie(response: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub fn validate_csrf(headers: &HeaderMap, submitted_token: Option<&str>) -> Result<(), AppError> {
    let cookie_token = parse_csrf_cookie(headers);
    let submitted_token = submitted_token.filter(|token| !token.is_empty());

    if cookie_token.as_deref().is_some() && cookie_token.as_deref() == submitted_token {
        return Ok(());
    }

    Err(AppError::from_code(CommonErrorCode::InvalidRequest))
}

// ─── Request helpers ──────────────────────────────────────────────────────────

/// Parse a `User-Agent` header with `woothee` and return device/browser/OS
/// fields.
pub fn parse_user_agent(
    headers: &HeaderMap,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let ua_str = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let raw_ua = if ua_str.is_empty() {
        None
    } else {
        Some(ua_str.to_owned())
    };

    let parser = woothee::parser::Parser::new();
    let result = parser.parse(ua_str);

    match result {
        Some(r) => (
            Some(r.name.to_owned()),        // device_name (browser name as device)
            Some(r.category.to_owned()),    // device_type (pc, smartphone, etc.)
            Some(r.os.to_owned()),          // os_name
            Some(r.os_version.to_string()), // os_version
            Some(r.name.to_owned()),        // browser_name
            Some(r.version.to_owned()),     // browser_version
            raw_ua,
        ),
        None => (None, None, None, None, None, None, raw_ua),
    }
}

pub fn build_session_context(headers: &HeaderMap) -> SessionContext {
    let (device_name, device_type, os_name, os_version, browser_name, browser_version, user_agent) =
        parse_user_agent(headers);
    let ip_address = extract_ip(headers);

    SessionContext {
        device_name,
        device_type,
        os_name,
        os_version,
        browser_name,
        browser_version,
        user_agent,
        ip_address,
    }
}

/// Extract the client IP address from proxy headers or fall back to
/// peer address.
pub fn extract_ip(headers: &HeaderMap) -> Option<String> {
    // X-Forwarded-For: client, proxy1, proxy2 — take the first.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let ip = xff.split(',').next().unwrap_or_default().trim();
        if !ip.is_empty() {
            return Some(ip.to_owned());
        }
    }
    // X-Real-Ip
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = xri.trim();
        if !ip.is_empty() {
            return Some(ip.to_owned());
        }
    }
    None
}
