//! Shared helpers for the authentication and OAuth protocol controllers.

use std::{convert::Infallible, net::IpAddr};

use http::{HeaderMap, HeaderValue, header};
use salvo::{
    Depot, Request, Response, async_trait,
    csrf::{
        BcryptCipher, CookieStore, Csrf, CsrfCipher, CsrfDepotExt, CsrfStore, CsrfTokenFinder,
        FormFinder, HeaderFinder, bcrypt_cookie_csrf,
    },
};
use uuid::Uuid;

use crate::{
    application::{
        auth::login::SessionContext,
        error::{AppError, codes::common::CommonErrorCode},
        setting::runtime::SettingProvider,
    },
    boot::AppState,
    controllers::response::redirect_to_response,
    domain::auth::model::{ActiveSession, SessionOid},
    domain::auth::{SESSION_COOKIE_NAME, SESSION_EXPIRY},
};

pub const CSRF_HEADER_NAME: &str = "x-csrf-token";
pub const CSRF_FORM_FIELD_NAME: &str = "csrf_token";
pub const SESSION_HEADER_NAME: &str = "x-sessions";
const API_CSRF_TOKEN_KEY: &str = "identity.api.csrf-token";
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
pub struct SelectedSessionState {
    pub protected_session_ids: Vec<String>,
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

pub fn protected_session_ids(headers: &HeaderMap) -> Vec<String> {
    headers
        .get(SESSION_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .or_else(|| {
            parse_cookie(headers, SESSION_COOKIE_NAME)
                .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        })
        .unwrap_or_default()
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

/// Parse protected sessions from `X-Sessions`, falling back to the legacy cookie.
///
/// The value is a JSON array of data-protected session IDs. Returns an empty
/// `Vec` when neither transport contains a valid array.
pub async fn parse_session_cookie(ctx: &AppState, headers: &HeaderMap) -> Vec<SessionCookieEntry> {
    let protected_ids = protected_session_ids(headers);

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
pub fn build_session_cookie_from_protected_ids(protected_ids: &[String]) -> String {
    let json = serde_json::to_string(protected_ids).unwrap_or_else(|_| "[]".to_owned());
    let max_age = SESSION_EXPIRY.as_secs();
    format!(
        "{SESSION_COOKIE_NAME}={json}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age={max_age}"
    )
}

pub async fn build_session_cookie(ctx: &AppState, oids: &[SessionOid]) -> Result<String, AppError> {
    #[cfg(test)]
    {
        let _ = ctx;
        let ids = oids
            .iter()
            .map(|oid| Uuid::from(*oid).to_string())
            .collect::<Vec<_>>();
        Ok(build_session_cookie_from_protected_ids(&ids))
    }

    #[cfg(not(test))]
    {
        let mut protected_ids = Vec::with_capacity(oids.len());
        for oid in oids {
            protected_ids.push(protect_session_id(ctx, *oid).await?);
        }
        Ok(build_session_cookie_from_protected_ids(&protected_ids))
    }
}

pub async fn build_selected_session_cookie(
    ctx: &AppState,
    headers: &HeaderMap,
    session_oid: SessionOid,
) -> Result<SelectedSessionCookie, AppError> {
    let state = build_selected_session_state(ctx, headers, session_oid).await?;
    Ok(SelectedSessionCookie {
        header: build_session_cookie_from_protected_ids(&state.protected_session_ids),
        protected_session_id: state.protected_session_id,
    })
}

pub async fn build_selected_session_state(
    ctx: &AppState,
    headers: &HeaderMap,
    session_oid: SessionOid,
) -> Result<SelectedSessionState, AppError> {
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

    Ok(SelectedSessionState {
        protected_session_ids: protected_ids,
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

pub fn append_set_cookie(response: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ApiCsrfHeaderStore;

impl CsrfStore for ApiCsrfHeaderStore {
    type Error = Infallible;

    async fn load<C: CsrfCipher>(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        cipher: &C,
    ) -> Option<(String, String)> {
        let value = req
            .headers()
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok())?;
        let (token, proof) = value.split_once('.')?;
        cipher
            .verify(token, proof)
            .then(|| (token.to_owned(), proof.to_owned()))
    }

    async fn save(
        &self,
        _req: &mut Request,
        depot: &mut Depot,
        _res: &mut Response,
        token: &str,
        proof: &str,
    ) -> Result<(), Self::Error> {
        depot.insert(API_CSRF_TOKEN_KEY, format!("{token}.{proof}"));
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ApiCsrfHeaderFinder;

#[async_trait]
impl CsrfTokenFinder for ApiCsrfHeaderFinder {
    async fn find_token(&self, req: &mut Request) -> Option<String> {
        req.headers()
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once('.'))
            .map(|(token, _)| token.to_owned())
    }
}

pub(crate) fn api_csrf_middleware() -> Csrf<BcryptCipher, ApiCsrfHeaderStore> {
    Csrf::new(BcryptCipher::new(), ApiCsrfHeaderStore, ApiCsrfHeaderFinder)
}

pub fn browser_csrf_middleware() -> Csrf<BcryptCipher, CookieStore> {
    bcrypt_cookie_csrf(HeaderFinder::new(CSRF_HEADER_NAME))
        .add_finder(FormFinder::new(CSRF_FORM_FIELD_NAME))
}

pub fn csrf_token(depot: &Depot) -> String {
    depot.get::<String>(API_CSRF_TOKEN_KEY).map_or_else(
        |_| depot.csrf_token().unwrap_or_default().to_owned(),
        Clone::clone,
    )
}

pub fn generate_csp_nonce() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
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
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(ip) = xff.split(',').next().and_then(parse_forwarded_ip)
    {
        return Some(ip);
    }
    // X-Real-Ip
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok())
        && let Some(ip) = parse_forwarded_ip(xri)
    {
        return Some(ip);
    }
    None
}

fn parse_forwarded_ip(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"');
    let value = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(value);
    value.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Redirect to the external login application with the protected interaction ID.
pub fn login_redirect(ctx: &AppState, login_id: &str) -> Result<Response, AppError> {
    interaction_redirect(
        ctx.settings().login_url().current_value().as_ref(),
        "login",
        login_id,
    )
}

/// Redirect to the external consent application with the protected interaction ID.
pub fn consent_redirect(ctx: &AppState, login_id: &str) -> Result<Response, AppError> {
    interaction_redirect(
        ctx.settings().consent_url().current_value().as_ref(),
        "consent",
        login_id,
    )
}

fn interaction_redirect(
    base: &Option<String>,
    interaction: &'static str,
    login_id: &str,
) -> Result<Response, AppError> {
    let base = base.as_deref().filter(|value| !value.trim().is_empty()).ok_or_else(|| {
        AppError::from_code(
            crate::application::error::codes::authorize_http::AuthorizeHttpErrorCode::InteractionUrlNotConfigured,
        )
        .with_param("interaction", interaction)
    })?;
    let separator = if base.contains('?') { '&' } else { '?' };
    let target = format!(
        "{base}{separator}login_id={}",
        urlencoding::encode(login_id)
    );
    Ok(redirect_to_response(&target))
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};
    use uuid::Uuid;

    #[test]
    fn build_session_cookie_is_always_secure_and_cross_site() {
        let cookie = super::build_session_cookie_from_protected_ids(&[Uuid::nil().to_string()]);

        assert!(cookie.contains("; HttpOnly; Secure; SameSite=None;"));
    }

    #[test]
    fn session_header_takes_precedence_over_legacy_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            super::SESSION_HEADER_NAME,
            HeaderValue::from_static("[\"header-session\"]"),
        );
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_static("sessions=[\"cookie-session\"]"),
        );

        assert_eq!(
            super::protected_session_ids(&headers),
            vec!["header-session"]
        );
    }

    #[test]
    fn extract_ip_accepts_first_forwarded_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 10.0.0.1"),
        );

        assert_eq!(super::extract_ip(&headers).as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn extract_ip_rejects_non_ip_header_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("unknown, attacker controlled"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("not-an-ip"));

        assert_eq!(super::extract_ip(&headers), None);
    }

    #[test]
    fn extract_ip_normalizes_bracketed_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("[2001:db8::1]"));

        assert_eq!(super::extract_ip(&headers).as_deref(), Some("2001:db8::1"));
    }
}
