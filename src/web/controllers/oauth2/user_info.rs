use http::{HeaderValue, StatusCode, header};
use identity_application::openid_connect::{dto::UserInfoClaims, user_info::TokenClaims};
use salvo::{
    Depot, Request, Response, Writer, async_trait, handler, handler::HoopedHandler, writing::Text,
};
use serde::Deserialize;
use serde_json::json;
use unic_langid::LanguageIdentifier;
use uuid::Uuid;

use super::pipeline::{Endpoint, Extract, RequireState, take};
use crate::{
    application::error::{
        AppError, code::AppErrorCode, codes::openid_connect::OpenIdConnectErrorCode,
        kind::ErrorKind,
    },
    controllers::response::{
        AppResponse, app_state, error_message, insert_no_store_headers, json_response,
    },
    infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers},
};

#[derive(Debug, Deserialize)]
struct UserInfoForm {
    access_token: Option<String>,
}

struct AccessToken(String);

struct UserInfoContext {
    client_id: Uuid,
    claims: UserInfoClaims,
}

pub fn get_endpoint() -> HoopedHandler {
    Endpoint::new("userinfo")
        .action("state", RequireState::<UserinfoWebError>::new())
        .action("read_bearer", read_bearer)
        .action("validate_token", validate_token)
        .action("load_claims", load_claims)
        .finish("protect_response", protect_response)
}

pub fn post_endpoint() -> HoopedHandler {
    Endpoint::new("userinfo")
        .action("state", RequireState::<UserinfoWebError>::new())
        .action(
            "parse_form",
            Extract::<UserInfoForm, UserinfoWebError>::form(),
        )
        .action("read_bearer", read_post_bearer)
        .action("validate_token", validate_token)
        .action("load_claims", load_claims)
        .finish("protect_response", protect_response)
}

#[handler]
async fn read_bearer(depot: &mut Depot, req: &mut Request) -> Result<(), UserinfoWebError> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::AuthorizationHeaderRequired))?;
    depot.insert_typed(AccessToken(parse_bearer_token(header)?.to_owned()));
    Ok(())
}

#[handler]
async fn read_post_bearer(depot: &mut Depot, req: &mut Request) -> Result<(), UserinfoWebError> {
    let form: UserInfoForm = take(depot)?;
    let token = if let Some(header) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        parse_bearer_token(header)?.to_owned()
    } else {
        form.access_token
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::AccessTokenRequired))?
    };
    depot.insert_typed(AccessToken(token));
    Ok(())
}

fn parse_bearer_token(header: &str) -> Result<&str, AppError> {
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::BearerSchemeInvalid))?;
    if token.is_empty() {
        return Err(AppError::from_code(
            OpenIdConnectErrorCode::AccessTokenRequired,
        ));
    }
    Ok(token)
}

#[handler]
async fn validate_token(depot: &mut Depot) -> Result<(), UserinfoWebError> {
    let ctx = app_state(depot)?;
    let token = take::<AccessToken>(depot)?.0;
    let claims = ctx
        .services()
        .user_info()
        .validate_access_token(&token)
        .await?;
    if !claims
        .audience
        .iter()
        .any(|audience| audience == &claims.client_oid.to_string())
    {
        return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken).into());
    }
    depot.insert_typed(claims);
    Ok(())
}

#[handler]
async fn load_claims(depot: &mut Depot) -> Result<(), UserinfoWebError> {
    let ctx = app_state(depot)?;
    let token: TokenClaims = take(depot)?;
    let claims = ctx
        .services()
        .user_info()
        .get_user_info(
            token.user_oid,
            token.client_oid,
            &token.scope,
            token.claims.as_ref(),
        )
        .await?;
    depot.insert_typed(UserInfoContext {
        client_id: token.client_oid,
        claims,
    });
    Ok(())
}

#[handler]
async fn protect_response(depot: &mut Depot) -> Result<AppResponse, UserinfoWebError> {
    let ctx = app_state(depot)?;
    let input: UserInfoContext = take(depot)?;
    let service = ctx.services().user_info();
    let signed = service
        .sign_user_info(input.client_id, &input.claims)
        .await?;
    if let Some(encrypted) = service
        .encrypt_user_info(input.client_id, &input.claims, signed.as_deref())
        .await?
    {
        return Ok(AppResponse(build_jose_response(encrypted)));
    }
    if let Some(signed) = signed {
        return Ok(AppResponse(build_jwt_response(signed)));
    }
    Ok(AppResponse(build_success_response(input.claims)))
}

fn build_success_response(claims: UserInfoClaims) -> Response {
    let mut response = json_response(StatusCode::OK, claims);
    insert_no_store_headers(&mut response);
    response
}

fn build_jose_response(token: String) -> Response {
    build_token_response(token, "application/jose")
}

fn build_jwt_response(token: String) -> Response {
    build_token_response(token, "application/jwt")
}

fn build_token_response(token: String, content_type: &'static str) -> Response {
    let mut response = Response::new();
    response.status_code(StatusCode::OK);
    response.render(Text::Plain(token));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Map an OIDC `AppError` to an RFC 6750 §3.1 `error` value.
///
/// Unlike the previous `error.kind()`-based mapping, this preserves the
/// specific error code so each failure surfaces its own Fluent message.
fn userinfo_rfc_error_code(error: &AppError) -> &'static str {
    match error.code() {
        c if c == OpenIdConnectErrorCode::InvalidToken.code() => "invalid_token",
        c if c == OpenIdConnectErrorCode::InsufficientScope.code() => "insufficient_scope",
        c if c == OpenIdConnectErrorCode::UserNotFound.code() => "invalid_request",
        c if c == OpenIdConnectErrorCode::BearerSchemeInvalid.code() => "invalid_request",
        c if c == OpenIdConnectErrorCode::AuthorizationHeaderRequired.code() => "invalid_request",
        c if c == OpenIdConnectErrorCode::AccessTokenRequired.code() => "invalid_request",
        _ => match error.kind() {
            ErrorKind::Unauthorized => "invalid_token",
            ErrorKind::Forbidden => "insufficient_scope",
            _ => "invalid_request",
        },
    }
}

fn userinfo_error_status(error: &AppError) -> StatusCode {
    match error.kind() {
        ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        // Bearer/header/access_token validation errors are 400 per RFC 6750.
        _ => StatusCode::BAD_REQUEST,
    }
}

/// Build the RFC 6750 userinfo error response body. The `error_description`
/// is resolved through Fluent using `locale`, keeping the message both
/// localized and specific to the underlying error code.
fn userinfo_error_response(error: AppError, i18n: &I18n, locale: &LanguageIdentifier) -> Response {
    let rfc_error = userinfo_rfc_error_code(&error);
    let description = error_message(i18n, locale, &error);
    let status = userinfo_error_status(&error);

    let error_body = json!({
        "error": rfc_error,
        "error_description": description
    });

    let mut response = json_response(status, error_body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&format!("Bearer error=\"{rfc_error}\"")) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// UserInfo endpoint error wrapper.
///
/// Always renders RFC 6750 §3.1 JSON (`{ "error", "error_description" }`) with
/// a `WWW-Authenticate` challenge header, regardless of the `Accept` header.
/// The `error_description` is localized via Fluent using the request's
/// `Accept-Language`, and the specific `AppError` code is preserved (rather
/// than collapsing every failure to a single generic literal).
pub struct UserinfoWebError(pub AppError);

impl From<AppError> for UserinfoWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for UserinfoWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        match error_i18n() {
            Some(i18n) => {
                let locale = resolve_locale_from_headers(req.headers());
                *res = userinfo_error_response(self.0, i18n, &locale);
            }
            None => {
                let rfc_error = userinfo_rfc_error_code(&self.0);
                let status = userinfo_error_status(&self.0);
                let error_body = json!({
                    "error": rfc_error,
                    "error_description": self.0.code().to_string()
                });
                let mut response = json_response(status, error_body);
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                if let Ok(value) = HeaderValue::from_str(&format!("Bearer error=\"{rfc_error}\"")) {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
                *res = response;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_bearer_token;

    #[test]
    fn parses_bearer_token_without_indexing_header_bytes() {
        assert_eq!(
            parse_bearer_token("Bearer token-value").unwrap(),
            "token-value"
        );
    }

    #[test]
    fn rejects_empty_bearer_token() {
        assert_eq!(parse_bearer_token("Bearer ").unwrap_err().code(), 21014);
    }

    #[test]
    fn rejects_non_bearer_authorization_scheme() {
        assert_eq!(
            parse_bearer_token("Basic credentials").unwrap_err().code(),
            21012
        );
    }
}
