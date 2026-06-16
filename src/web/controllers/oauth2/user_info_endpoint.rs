use http::{HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, handler, writing::Text};
use serde::Deserialize;
use unic_langid::LanguageIdentifier;

use crate::controllers::response::{
    AppResponse, app_state, error_message, insert_no_store_headers, json_response, parse_form,
};
use crate::infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers};
use crate::{
    application::error::{
        AppError, code::AppErrorCode, codes::openid_connect::OpenIdConnectErrorCode,
        kind::ErrorKind,
    },
    boot::AppState,
};

#[derive(Debug, Deserialize)]
struct UserInfoForm {
    access_token: Option<String>,
}

#[handler]
pub async fn userinfo(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, UserinfoWebError> {
    let ctx = app_state(depot).map_err(UserinfoWebError)?;
    let headers = req.headers().clone();
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());

    let bearer_token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        Some(_) => {
            return Err(UserinfoWebError(AppError::from_code(
                OpenIdConnectErrorCode::BearerSchemeInvalid,
            )))
        }
        None => {
            return Err(UserinfoWebError(AppError::from_code(
                OpenIdConnectErrorCode::AuthorizationHeaderRequired,
            )))
        }
    };

    handle_userinfo_request(ctx, bearer_token).await
}

#[handler]
pub async fn userinfo_post(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, UserinfoWebError> {
    let ctx = app_state(depot).map_err(UserinfoWebError)?;
    let headers = req.headers().clone();
    let form: UserInfoForm = parse_form(req).await.map_err(UserinfoWebError)?;
    // Token may come from Authorization header or POST body
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());

    let bearer_token: String = if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            token.to_string()
        } else {
            return Err(UserinfoWebError(AppError::from_code(
                OpenIdConnectErrorCode::BearerSchemeInvalid,
            )));
        }
    } else if let Some(token) = form.access_token {
        token
    } else {
        return Err(UserinfoWebError(AppError::from_code(
            OpenIdConnectErrorCode::AccessTokenRequired,
        )));
    };

    handle_userinfo_request(ctx, &bearer_token).await
}

async fn handle_userinfo_request(
    ctx: AppState,
    token: &str,
) -> Result<AppResponse, UserinfoWebError> {
    let service = ctx.services().user_info();

    let token_claims = service.validate_access_token(token).await.map_err(UserinfoWebError)?;

    let user_claims = service
        .get_user_info(
            token_claims.user_oid,
            token_claims.client_oid,
            &token_claims.scope,
            token_claims.claims.as_ref(),
        )
        .await
        .map_err(UserinfoWebError)?;

    match service
        .encrypt_user_info(token_claims.client_oid, &user_claims)
        .await
    {
        Ok(Some(encrypted)) => return Ok(AppResponse(build_jose_response(encrypted))),
        Ok(None) => {}
        Err(error) => return Err(UserinfoWebError(error)),
    }

    match service
        .sign_user_info(token_claims.client_oid, &user_claims)
        .await
    {
        Ok(Some(signed)) => return Ok(AppResponse(build_jwt_response(signed))),
        Ok(None) => {}
        Err(error) => return Err(UserinfoWebError(error)),
    }

    Ok(AppResponse(build_success_response(user_claims)))
}

fn build_success_response(claims: identity_application::openid_connect::dto::UserInfoClaims) -> Response {
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

    let error_body = serde_json::json!({
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
                let error_body = serde_json::json!({
                    "error": rfc_error,
                    "error_description": self.0.code().to_string()
                });
                let mut response = json_response(status, error_body);
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                );
                if let Ok(value) = HeaderValue::from_str(&format!("Bearer error=\"{rfc_error}\""))
                {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
                *res = response;
            }
        }
    }
}
