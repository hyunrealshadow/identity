use std::borrow::Cow;

use http::{HeaderMap, HeaderValue, StatusCode, header};
use identity_application::error::{
    AppError,
    code::AppErrorCode,
    codes::{common::CommonErrorCode, token::TokenErrorCode},
    kind::ErrorKind,
};
use salvo::{Depot, Request, Response, Writer, async_trait};
use serde::Serialize;
use unic_langid::LanguageIdentifier;

use super::super::error::Rfc6749Error;
use crate::{
    controllers::response::{error_message, insert_no_store_headers, json_response, log_app_error},
    infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers},
};

/// RFC 6749 §5.2 token error response.
#[derive(Debug, Serialize)]
struct TokenErrorResponse {
    error: Cow<'static, str>,
    error_description: String,
}

/// Build the RFC 6749 §5.2 token error response body.
///
/// `error_description` is resolved through the Fluent i18n system (respecting
/// `locale`) rather than a hardcoded English template, so the description is
/// both localized and as specific as the underlying `AppError` code allows.
pub(super) fn token_error_response(
    error: impl Into<TokenWebError>,
    i18n: &I18n,
    locale: &LanguageIdentifier,
) -> Response {
    let error = error.into();
    let status = error.rfc6749_status();
    let description = error_message(i18n, locale, error.app_error());
    let body = TokenErrorResponse {
        error: error.rfc6749_error_code(),
        error_description: description,
    };

    let mut response = json_response(status, body);
    insert_no_store_headers(&mut response);
    response
}

/// Token endpoint error wrapper.
///
/// The token endpoint must always return RFC 6749 §5.2 JSON
/// (`{ "error", "error_description" }`) with the spec-mandated status codes
/// (e.g. `invalid_client` → 401), regardless of the `Accept` header. The
/// `error_description` is localized via Fluent using the request's
/// `Accept-Language`.
pub(in crate::controllers::oauth2) struct TokenWebError(pub(super) AppError);

impl From<AppError> for TokenWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

impl Rfc6749Error for TokenWebError {
    fn app_error(&self) -> &AppError {
        &self.0
    }

    fn rfc6749_error_code(&self) -> Cow<'static, str> {
        Cow::Borrowed(token_error_code(&self.0))
    }
}

#[async_trait]
impl Writer for TokenWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        log_app_error(&self.0, "token endpoint request failed");
        match error_i18n() {
            Some(i18n) => {
                let locale = resolve_locale_from_headers(req.headers());
                let response = token_error_response(self, i18n, &locale);
                *res = response;
            }
            None => {
                let status = self.rfc6749_status();
                let body = TokenErrorResponse {
                    error: self.rfc6749_error_code(),
                    error_description: self.0.code().to_string(),
                };
                let mut response = json_response(status, body);
                insert_no_store_headers(&mut response);
                *res = response;
            }
        }
    }
}

pub(in crate::controllers::oauth2) fn token_error_code(error: &AppError) -> &'static str {
    match error.code() {
        code if code == CommonErrorCode::InvalidScope.code() => "invalid_scope",
        c if c == CommonErrorCode::InvalidTarget.code() => "invalid_target",
        // Authorization code errors → invalid_grant
        c if c == TokenErrorCode::AuthCodeNotFound.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeInvalid.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeRevoked.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeExpired.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeSessionNotFound.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeSessionInactive.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeSessionRevoked.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeSessionExpired.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeSessionUserMismatch.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeClaimFailed.code() => "invalid_grant",
        c if c == TokenErrorCode::CodeClientMismatch.code() => "invalid_grant",
        c if c == TokenErrorCode::RedirectUriMismatch.code() => "invalid_grant",
        c if c == TokenErrorCode::PkceVerifierMismatch.code() => "invalid_grant",
        c if c == TokenErrorCode::CodeVerifierRequired.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeUserNotFound.code() => "invalid_grant",
        // Refresh token errors → invalid_grant
        c if c == TokenErrorCode::RefreshTokenNotFound.code() => "invalid_grant",
        c if c == TokenErrorCode::RefreshTokenInvalid.code() => "invalid_grant",
        c if c == TokenErrorCode::RefreshTokenClientMismatch.code() => "invalid_grant",
        c if c == TokenErrorCode::RefreshTokenUserNotFound.code() => "invalid_grant",
        c if c == TokenErrorCode::RefreshTokenVerifyFailed.code() => "invalid_grant",
        // Client auth errors → invalid_client
        c if c == TokenErrorCode::ClientNotFound.code() => "invalid_client",
        c if c == TokenErrorCode::ClientCredentialsInvalid.code() => "invalid_client",
        c if c == TokenErrorCode::ClientAuthRequired.code() => "invalid_client",
        c if c == TokenErrorCode::RefreshScopeNotAllowed.code() => "invalid_scope",
        c if c == TokenErrorCode::ClientCredentialsScopeNotAllowed.code() => "invalid_scope",
        c if c == TokenErrorCode::AssertionVerifyFailed.code() => "invalid_client",
        c if c == TokenErrorCode::AssertionExpired.code() => "invalid_client",
        c if c == TokenErrorCode::AssertionAudMismatch.code() => "invalid_client",
        c if c == TokenErrorCode::AssertionIssSubMismatch.code() => "invalid_client",
        // Unsupported grant type
        c if c == TokenErrorCode::UnsupportedGrantType.code() => "unsupported_grant_type",
        // Client is not permitted to use the requested grant
        c if c == TokenErrorCode::ClientGrantNotAllowed.code() => "unauthorized_client",
        // Device authorization grant (RFC 8628 §3.5)
        c if c == TokenErrorCode::DeviceCodePending.code() => "authorization_pending",
        c if c == TokenErrorCode::DeviceCodeSlowDown.code() => "slow_down",
        c if c == TokenErrorCode::DeviceCodeDenied.code()
            || c == TokenErrorCode::DeviceCodeRevoked.code() =>
        {
            "access_denied"
        }
        c if c == TokenErrorCode::DeviceCodeExpired.code() => "expired_token",
        c if c == TokenErrorCode::DeviceCodeNotFound.code()
            || c == TokenErrorCode::DeviceCodeClientMismatch.code()
            || c == TokenErrorCode::DeviceCodeUserNotFound.code()
            || c == TokenErrorCode::DeviceRequestStateInvalid.code() =>
        {
            "invalid_grant"
        }
        c if c == TokenErrorCode::DeviceRequestLookupFailed.code()
            || c == TokenErrorCode::DeviceRelationLookupFailed.code()
            || c == TokenErrorCode::DeviceRedemptionFailed.code() =>
        {
            "server_error"
        }
        // Everything else
        _ => match error.kind() {
            ErrorKind::Validation => "invalid_request",
            _ => "server_error",
        },
    }
}

fn inspection_error_code(error: &AppError) -> &'static str {
    let code = error.code();
    if [
        TokenErrorCode::ClientNotFound,
        TokenErrorCode::ClientIdInvalid,
        TokenErrorCode::ClientCredentialsInvalid,
        TokenErrorCode::ClientAuthRequired,
        TokenErrorCode::AssertionIssMissing,
        TokenErrorCode::AssertionSubMissing,
        TokenErrorCode::AssertionVerifyFailed,
        TokenErrorCode::AssertionExpired,
        TokenErrorCode::AssertionNotYetValid,
        TokenErrorCode::AssertionHeaderInvalid,
        TokenErrorCode::AssertionAlgUnsupported,
        TokenErrorCode::AssertionKeyInvalid,
        TokenErrorCode::AssertionAudMismatch,
        TokenErrorCode::AssertionIssSubMismatch,
    ]
    .iter()
    .any(|candidate| code == candidate.code())
    {
        "invalid_client"
    } else if error.kind() == ErrorKind::Internal {
        "server_error"
    } else {
        "invalid_request"
    }
}

fn inspection_error_response(
    error: AppError,
    headers: &HeaderMap,
    challenge: &'static str,
) -> Response {
    let code = inspection_error_code(&error);
    let status = match code {
        "invalid_client" => StatusCode::UNAUTHORIZED,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    let description = error_i18n()
        .map(|i18n| error_message(i18n, &resolve_locale_from_headers(headers), &error))
        .unwrap_or_else(|| error.code().to_string());
    let mut response = json_response(
        status,
        TokenErrorResponse {
            error: Cow::Borrowed(code),
            error_description: description,
        },
    );
    insert_no_store_headers(&mut response);
    if status == StatusCode::UNAUTHORIZED && headers.contains_key(header::AUTHORIZATION) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(challenge),
        );
    }
    response
}

pub(super) struct IntrospectionWebError(AppError);

impl From<AppError> for IntrospectionWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for IntrospectionWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        *res =
            inspection_error_response(self.0, req.headers(), "Basic realm=\"oauth2/introspect\"");
    }
}

pub(super) struct RevocationWebError(AppError);

impl From<AppError> for RevocationWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for RevocationWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        *res = inspection_error_response(self.0, req.headers(), "Basic realm=\"oauth2/revoke\"");
    }
}
