//! Shared helpers used by both the JSON API (`auth`) and the SSR UI (`auth_ui`)
//! controllers. Keeping them here avoids duplication and ensures both surfaces
//! behave identically for cookie handling, etc.

use http::{HeaderMap, HeaderValue, header};
use salvo::{
    Depot, Response,
    csrf::{CsrfDepotExt, FormFinder, HeaderFinder, JsonFinder, bcrypt_cookie_csrf},
};
use uuid::Uuid;

use crate::{
    application::{
        auth::login::SessionContext,
        error::{AppError, codes::common::CommonErrorCode},
    },
    boot::AppState,
    domain::auth::model::{ActiveSession, SessionOid},
    domain::auth::{SESSION_COOKIE_NAME, SESSION_EXPIRY},
};

pub const CSRF_HEADER_NAME: &str = "x-csrf-token";
pub const CSRF_FORM_FIELD_NAME: &str = "csrf_token";
const SESSION_ID_PROTECTION_PURPOSE: &str = "session-id";

#[derive(Debug, Clone)]
pub struct ActiveSessionEntry {
    pub session: ActiveSession,
    pub protected_session_id: String,
}

#[derive(Debug, Clone)]
pub struct SelectedSessionCookie {
    pub header: String,
    pub protected_session_id: String,
}

#[derive(Debug, Clone)]
pub struct SessionCookieEntry {
    pub session_oid: SessionOid,
    pub protected_session_id: String,
}

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

pub async fn protect_session_id(
    ctx: &AppState,
    session_oid: SessionOid,
) -> Result<String, AppError> {
    ctx.services()
        .data_protector()
        .protect(
            SESSION_ID_PROTECTION_PURPOSE,
            Uuid::from(session_oid).as_bytes(),
        )
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error))
}

pub async fn unprotect_session_id(
    ctx: &AppState,
    protected_id: &str,
) -> Result<SessionOid, AppError> {
    let bytes = ctx
        .services()
        .data_protector()
        .unprotect(SESSION_ID_PROTECTION_PURPOSE, protected_id)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error))?;

    let uuid = Uuid::from_slice(&bytes)
        .map_err(|error| AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error))?;
    Ok(SessionOid(uuid))
}

/// Parse the `sessions` cookie from request headers.
///
/// The cookie value is a JSON array of data-protected session IDs. Returns an
/// empty `Vec` when the cookie is absent or malformed.
pub async fn parse_session_cookie(ctx: &AppState, headers: &HeaderMap) -> Vec<SessionCookieEntry> {
    let protected_ids = parse_cookie(headers, SESSION_COOKIE_NAME)
        .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        .unwrap_or_default();

    let mut entries = Vec::new();
    for protected_session_id in protected_ids {
        if let Ok(session_oid) = unprotect_session_id(ctx, &protected_session_id).await {
            entries.push(SessionCookieEntry {
                session_oid,
                protected_session_id,
            });
            continue;
        }

        #[cfg(test)]
        if let Ok(session_oid) = Uuid::parse_str(&protected_session_id) {
            entries.push(SessionCookieEntry {
                session_oid: SessionOid(session_oid),
                protected_session_id,
            });
        }
    }
    entries
}

/// Build the `Set-Cookie` header value for the sessions cookie.
///
/// Set `secure = true` in production so the cookie is only sent over HTTPS.
pub fn build_session_cookie_from_protected_ids(protected_ids: &[String], secure: bool) -> String {
    let json = serde_json::to_string(protected_ids).unwrap_or_else(|_| "[]".to_owned());
    let max_age = SESSION_EXPIRY.as_secs();
    let secure_flag = if secure { "; Secure" } else { "" };
    let same_site = if secure { "None" } else { "Lax" };
    format!(
        "{SESSION_COOKIE_NAME}={json}; HttpOnly{secure_flag}; SameSite={same_site}; Path=/; Max-Age={max_age}"
    )
}

pub async fn build_session_cookie(
    ctx: &AppState,
    oids: &[SessionOid],
    secure: bool,
) -> Result<String, AppError> {
    #[cfg(test)]
    {
        let _ = ctx;
        let ids = oids
            .iter()
            .map(|oid| Uuid::from(*oid).to_string())
            .collect::<Vec<_>>();
        Ok(build_session_cookie_from_protected_ids(&ids, secure))
    }

    #[cfg(not(test))]
    {
        let mut protected_ids = Vec::with_capacity(oids.len());
        for oid in oids {
            protected_ids.push(protect_session_id(ctx, *oid).await?);
        }
        Ok(build_session_cookie_from_protected_ids(
            &protected_ids,
            secure,
        ))
    }
}

pub async fn build_selected_session_cookie(
    ctx: &AppState,
    headers: &HeaderMap,
    session_oid: SessionOid,
    secure: bool,
) -> Result<SelectedSessionCookie, AppError> {
    let mut entries = parse_session_cookie(ctx, headers).await;
    let existing = entries
        .iter()
        .find(|entry| entry.session_oid == session_oid)
        .map(|entry| entry.protected_session_id.clone());
    let protected_session_id = match existing {
        Some(id) => id,
        None => protect_session_id(ctx, session_oid).await?,
    };

    entries.retain(|entry| entry.session_oid != session_oid);
    let mut protected_ids = Vec::with_capacity(entries.len() + 1);
    protected_ids.push(protected_session_id.clone());
    protected_ids.extend(entries.into_iter().map(|entry| entry.protected_session_id));

    Ok(SelectedSessionCookie {
        header: build_session_cookie_from_protected_ids(&protected_ids, secure),
        protected_session_id,
    })
}

pub async fn load_active_session_entries(
    ctx: &AppState,
    headers: &HeaderMap,
) -> Result<Vec<ActiveSessionEntry>, AppError> {
    let entries = parse_session_cookie(ctx, headers).await;

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let session_oids: Vec<SessionOid> = entries.iter().map(|entry| entry.session_oid).collect();
    let active_sessions = ctx
        .services()
        .session()
        .get_active_accounts(&session_oids)
        .await?;

    Ok(active_sessions
        .into_iter()
        .filter_map(|session| {
            entries
                .iter()
                .find(|entry| entry.session_oid == session.session_oid)
                .map(|entry| ActiveSessionEntry {
                    session,
                    protected_session_id: entry.protected_session_id.clone(),
                })
        })
        .collect())
}

pub async fn load_active_sessions(
    ctx: &AppState,
    headers: &HeaderMap,
) -> Result<Vec<ActiveSession>, AppError> {
    Ok(load_active_session_entries(ctx, headers)
        .await?
        .into_iter()
        .map(|entry| entry.session)
        .collect())
}

/// Return `true` when the app is running in the `production` environment,
/// which triggers the `Secure` flag on session cookies.
pub fn is_secure_cookie(ctx: &AppState) -> bool {
    if ctx.context().is_production() {
        return true;
    }

    #[cfg(feature = "oidc-conformance")]
    if ctx.context().is_conformance() {
        return true;
    }

    false
}

pub fn append_set_cookie(response: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub fn csrf_middleware() -> salvo::csrf::Csrf<salvo::csrf::BcryptCipher, salvo::csrf::CookieStore> {
    bcrypt_cookie_csrf(HeaderFinder::new(CSRF_HEADER_NAME))
        .add_finder(FormFinder::new(CSRF_FORM_FIELD_NAME))
        .add_finder(JsonFinder::new(CSRF_FORM_FIELD_NAME))
}

pub fn csrf_token(depot: &Depot) -> String {
    depot.csrf_token().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    #[test]
    fn build_session_cookie_uses_lax_without_secure_flag() {
        let cookie =
            super::build_session_cookie_from_protected_ids(&[Uuid::nil().to_string()], false);

        assert!(cookie.contains("; HttpOnly; SameSite=Lax;"));
        assert!(!cookie.contains("; Secure;"));
    }

    #[test]
    fn build_session_cookie_uses_none_when_secure_for_iframe_session_checks() {
        let cookie =
            super::build_session_cookie_from_protected_ids(&[Uuid::nil().to_string()], true);

        assert!(cookie.contains("; HttpOnly; Secure; SameSite=None;"));
    }
}

// ─── Request helpers ──────────────────────────────────────────────────────────

/// Parse a `User-Agent` header with `woothee` and return device/browser/OS
/// fields.
pub type ParsedUserAgent = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub fn parse_user_agent(headers: &HeaderMap) -> ParsedUserAgent {
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
