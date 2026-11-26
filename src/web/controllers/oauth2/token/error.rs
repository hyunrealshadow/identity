use std::borrow::Cow;

use crate::error::{error_message, log_app_error, request_error_message, with_request_catalog};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use identity_application::error::{
    AppError, ErrorCode,
    codes::{common::CommonErrorCode, token::TokenErrorCode},
    kind::ErrorKind,
};
use salvo::{Depot, Request, Response, Writer, async_trait};
use serde::Serialize;
use unic_langid::LanguageIdentifier;

use super::super::error::Rfc6749Error;
use crate::{
    controllers::response::{insert_no_store_headers, json_response},
    infrastructure::i18n::I18n,
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
        *res = with_request_catalog(req.headers(), |i18n, locale| {
            token_error_response(self, i18n, locale)
        });
    }
}

pub(in crate::controllers::oauth2) fn is_client_auth_token_error(code: TokenErrorCode) -> bool {
    match code {
        TokenErrorCode::ClientIdInvalid
        | TokenErrorCode::ClientNotFound
        | TokenErrorCode::ClientCredentialsInvalid
        | TokenErrorCode::ClientAuthRequired
        | TokenErrorCode::AssertionIssMissing
        | TokenErrorCode::AssertionSubMissing
        | TokenErrorCode::AssertionIssSubMismatch
        | TokenErrorCode::AssertionAudMismatch
        | TokenErrorCode::AssertionExpired
        | TokenErrorCode::AssertionNotYetValid
        | TokenErrorCode::AssertionHeaderInvalid
        | TokenErrorCode::AssertionVerifyFailed
        | TokenErrorCode::AssertionAlgUnsupported
        | TokenErrorCode::AssertionKeyInvalid => true,
        TokenErrorCode::UnsupportedGrantType
        | TokenErrorCode::ClientIdRequired
        | TokenErrorCode::CodeLookupFailed
        | TokenErrorCode::AuthCodeNotFound
        | TokenErrorCode::CodeClientMismatch
        | TokenErrorCode::AuthCodeInvalid
        | TokenErrorCode::AuthCodeRevoked
        | TokenErrorCode::AuthCodeExpired
        | TokenErrorCode::AuthCodeSessionNotFound
        | TokenErrorCode::AuthCodeSessionInactive
        | TokenErrorCode::AuthCodeSessionRevoked
        | TokenErrorCode::AuthCodeSessionExpired
        | TokenErrorCode::AuthCodeSessionUserMismatch
        | TokenErrorCode::AuthCodeClaimFailed
        | TokenErrorCode::AuthCodeSessionLookupFailed
        | TokenErrorCode::DeserializeCodeFailed
        | TokenErrorCode::RedirectUriMismatch
        | TokenErrorCode::CodeVerifierRequired
        | TokenErrorCode::StoredUserOidInvalid
        | TokenErrorCode::UserLookupFailed
        | TokenErrorCode::AuthCodeUserNotFound
        | TokenErrorCode::RevokeCodeFailed
        | TokenErrorCode::RefreshTokenLookupFailed
        | TokenErrorCode::RefreshTokenNotFound
        | TokenErrorCode::RefreshTokenInvalid
        | TokenErrorCode::DeserializeRefreshFailed
        | TokenErrorCode::RefreshTokenSubMissing
        | TokenErrorCode::RefreshTokenUseMissing
        | TokenErrorCode::RefreshTokenUseInvalid
        | TokenErrorCode::RefreshTokenClientMismatch
        | TokenErrorCode::RefreshTokenSubInvalid
        | TokenErrorCode::RefreshTokenUserNotFound
        | TokenErrorCode::RevokeRefreshFailed
        | TokenErrorCode::KeyListFailed
        | TokenErrorCode::NoSigningKeyAvailable
        | TokenErrorCode::ClientLookupFailed
        | TokenErrorCode::CredentialLookupFailed
        | TokenErrorCode::RefreshTokenVerifyFailed
        | TokenErrorCode::SignAccessTokenFailed
        | TokenErrorCode::SignIdTokenFailed
        | TokenErrorCode::SignRefreshTokenFailed
        | TokenErrorCode::SerializeRefreshFailed
        | TokenErrorCode::StoreRefreshFailed
        | TokenErrorCode::PkceMethodUnsupported
        | TokenErrorCode::PkceVerifierMismatch
        | TokenErrorCode::EncryptionKeyNotFound
        | TokenErrorCode::EncryptionFailed
        | TokenErrorCode::ClientGrantNotAllowed
        | TokenErrorCode::DeviceCodeNotFound
        | TokenErrorCode::DeviceCodeClientMismatch
        | TokenErrorCode::DeviceCodePending
        | TokenErrorCode::DeviceCodeSlowDown
        | TokenErrorCode::DeviceCodeDenied
        | TokenErrorCode::DeviceCodeExpired
        | TokenErrorCode::DeviceCodeRevoked
        | TokenErrorCode::DeviceCodeUserNotFound
        | TokenErrorCode::DeviceRequestStateInvalid
        | TokenErrorCode::DeviceRequestLookupFailed
        | TokenErrorCode::DeviceRelationLookupFailed
        | TokenErrorCode::DeviceRedemptionFailed
        | TokenErrorCode::RefreshScopeNotAllowed
        | TokenErrorCode::ClientCredentialsScopeNotAllowed => false,
    }
}

fn token_code_to_rfc6749(code: TokenErrorCode) -> &'static str {
    if is_client_auth_token_error(code) {
        return "invalid_client";
    }
    match code {
        TokenErrorCode::ClientIdRequired
        | TokenErrorCode::RefreshTokenSubMissing
        | TokenErrorCode::RefreshTokenUseMissing
        | TokenErrorCode::RefreshTokenUseInvalid
        | TokenErrorCode::RefreshTokenSubInvalid
        | TokenErrorCode::PkceMethodUnsupported => "invalid_request",
        TokenErrorCode::AuthCodeNotFound
        | TokenErrorCode::CodeClientMismatch
        | TokenErrorCode::AuthCodeInvalid
        | TokenErrorCode::AuthCodeRevoked
        | TokenErrorCode::AuthCodeExpired
        | TokenErrorCode::AuthCodeSessionNotFound
        | TokenErrorCode::AuthCodeSessionInactive
        | TokenErrorCode::AuthCodeSessionRevoked
        | TokenErrorCode::AuthCodeSessionExpired
        | TokenErrorCode::AuthCodeSessionUserMismatch
        | TokenErrorCode::AuthCodeClaimFailed
        | TokenErrorCode::RedirectUriMismatch
        | TokenErrorCode::CodeVerifierRequired
        | TokenErrorCode::AuthCodeUserNotFound
        | TokenErrorCode::RefreshTokenNotFound
        | TokenErrorCode::RefreshTokenInvalid
        | TokenErrorCode::RefreshTokenClientMismatch
        | TokenErrorCode::RefreshTokenUserNotFound
        | TokenErrorCode::RefreshTokenVerifyFailed
        | TokenErrorCode::PkceVerifierMismatch
        | TokenErrorCode::DeviceCodeNotFound
        | TokenErrorCode::DeviceCodeClientMismatch
        | TokenErrorCode::DeviceCodeUserNotFound
        | TokenErrorCode::DeviceRequestStateInvalid => "invalid_grant",
        TokenErrorCode::RefreshScopeNotAllowed
        | TokenErrorCode::ClientCredentialsScopeNotAllowed => "invalid_scope",
        TokenErrorCode::UnsupportedGrantType => "unsupported_grant_type",
        TokenErrorCode::ClientGrantNotAllowed => "unauthorized_client",
        TokenErrorCode::DeviceCodePending => "authorization_pending",
        TokenErrorCode::DeviceCodeSlowDown => "slow_down",
        TokenErrorCode::DeviceCodeDenied | TokenErrorCode::DeviceCodeRevoked => "access_denied",
        TokenErrorCode::DeviceCodeExpired => "expired_token",
        TokenErrorCode::CodeLookupFailed
        | TokenErrorCode::AuthCodeSessionLookupFailed
        | TokenErrorCode::DeserializeCodeFailed
        | TokenErrorCode::StoredUserOidInvalid
        | TokenErrorCode::UserLookupFailed
        | TokenErrorCode::RevokeCodeFailed
        | TokenErrorCode::RefreshTokenLookupFailed
        | TokenErrorCode::DeserializeRefreshFailed
        | TokenErrorCode::RevokeRefreshFailed
        | TokenErrorCode::KeyListFailed
        | TokenErrorCode::NoSigningKeyAvailable
        | TokenErrorCode::ClientLookupFailed
        | TokenErrorCode::CredentialLookupFailed
        | TokenErrorCode::SignAccessTokenFailed
        | TokenErrorCode::SignIdTokenFailed
        | TokenErrorCode::SignRefreshTokenFailed
        | TokenErrorCode::SerializeRefreshFailed
        | TokenErrorCode::StoreRefreshFailed
        | TokenErrorCode::EncryptionKeyNotFound
        | TokenErrorCode::EncryptionFailed
        | TokenErrorCode::DeviceRequestLookupFailed
        | TokenErrorCode::DeviceRelationLookupFailed
        | TokenErrorCode::DeviceRedemptionFailed => "server_error",
        TokenErrorCode::ClientIdInvalid
        | TokenErrorCode::ClientNotFound
        | TokenErrorCode::ClientCredentialsInvalid
        | TokenErrorCode::ClientAuthRequired
        | TokenErrorCode::AssertionIssMissing
        | TokenErrorCode::AssertionSubMissing
        | TokenErrorCode::AssertionIssSubMismatch
        | TokenErrorCode::AssertionAudMismatch
        | TokenErrorCode::AssertionExpired
        | TokenErrorCode::AssertionNotYetValid
        | TokenErrorCode::AssertionHeaderInvalid
        | TokenErrorCode::AssertionVerifyFailed
        | TokenErrorCode::AssertionAlgUnsupported
        | TokenErrorCode::AssertionKeyInvalid => "invalid_client",
    }
}

pub(in crate::controllers::oauth2) fn token_error_code(error: &AppError) -> &'static str {
    match error.error_code() {
        ErrorCode::Token(code) => token_code_to_rfc6749(code),
        ErrorCode::Common(CommonErrorCode::InvalidScope) => "invalid_scope",
        ErrorCode::Common(CommonErrorCode::InvalidTarget) => "invalid_target",
        _ => match error.kind() {
            ErrorKind::Validation => "invalid_request",
            _ => "server_error",
        },
    }
}

fn inspection_error_code(error: &AppError) -> &'static str {
    match error.error_code() {
        ErrorCode::Token(code) if is_client_auth_token_error(code) => "invalid_client",
        _ if error.kind() == ErrorKind::Internal => "server_error",
        _ => "invalid_request",
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
    let description = request_error_message(headers, &error);
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
