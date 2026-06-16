use base64::Engine;
use http::{HeaderMap, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, handler};
use serde::{Deserialize, Serialize};
use unic_langid::LanguageIdentifier;

use identity_application::{
    error::{AppError, code::AppErrorCode, codes::token::TokenErrorCode, kind::ErrorKind},
    openid_connect::token::{AuthorizationCodeGrantParams, RefreshTokenGrantParams},
};

use crate::controllers::response::{
    AppResponse, app_state, error_message, insert_no_store_headers, json_response, parse_form,
};
use crate::infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers};

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    code_verifier: Option<String>,
}

/// RFC 6749 §5.2 token error response.
#[derive(Debug, Serialize)]
struct TokenErrorResponse {
    error: &'static str,
    error_description: String,
}

fn app_error_to_rfc6749(error: &AppError) -> &'static str {
    match error.code() {
        // Authorization code errors → invalid_grant
        c if c == TokenErrorCode::AuthCodeNotFound.code() => "invalid_grant",
        c if c == TokenErrorCode::AuthCodeInvalid.code() => "invalid_grant",
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
        c if c == TokenErrorCode::AssertionVerifyFailed.code() => "invalid_client",
        c if c == TokenErrorCode::AssertionExpired.code() => "invalid_client",
        c if c == TokenErrorCode::AssertionAudMismatch.code() => "invalid_client",
        c if c == TokenErrorCode::AssertionIssSubMismatch.code() => "invalid_client",
        // Unsupported grant type
        c if c == TokenErrorCode::UnsupportedGrantType.code() => "unsupported_grant_type",
        // Everything else
        _ => match error.kind() {
            ErrorKind::Validation => "invalid_request",
            _ => "server_error",
        },
    }
}

fn token_error_status(error: &AppError) -> StatusCode {
    if error.kind() == ErrorKind::Internal {
        StatusCode::INTERNAL_SERVER_ERROR
    } else if app_error_to_rfc6749(error) == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// Build the RFC 6749 §5.2 token error response body.
///
/// `error_description` is resolved through the Fluent i18n system (respecting
/// `locale`) rather than a hardcoded English template, so the description is
/// both localized and as specific as the underlying `AppError` code allows.
fn token_error_response(error: AppError, i18n: &I18n, locale: &LanguageIdentifier) -> Response {
    let status = token_error_status(&error);
    let description = error_message(i18n, locale, &error);
    let body = TokenErrorResponse {
        error: app_error_to_rfc6749(&error),
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
pub struct TokenWebError(pub AppError);

impl From<AppError> for TokenWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for TokenWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        match error_i18n() {
            Some(i18n) => {
                let locale = resolve_locale_from_headers(req.headers());
                let response = token_error_response(self.0, i18n, &locale);
                *res = response;
            }
            None => {
                let status = token_error_status(&self.0);
                let body = TokenErrorResponse {
                    error: app_error_to_rfc6749(&self.0),
                    error_description: self.0.code().to_string(),
                };
                let mut response = json_response(status, body);
                insert_no_store_headers(&mut response);
                *res = response;
            }
        }
    }
}

fn parse_basic_client_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;
    Some((client_id.to_string(), client_secret.to_string()))
}

#[handler]
pub async fn token(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, TokenWebError> {
    let ctx = app_state(depot).map_err(TokenWebError)?;
    let headers: HeaderMap = req.headers().clone();
    let form: TokenForm = parse_form(req).await.map_err(TokenWebError)?;
    let basic_auth = parse_basic_client_auth(&headers);
    let client_id = basic_auth
        .as_ref()
        .map(|value| value.0.clone())
        .or(form.client_id);
    let client_secret = basic_auth
        .as_ref()
        .map(|value| value.1.clone())
        .or(form.client_secret);

    let result = match form.grant_type.as_str() {
        "authorization_code" => {
            ctx.services()
                .oidc_token()
                .exchange_authorization_code(AuthorizationCodeGrantParams {
                    grant_type: form.grant_type,
                    code: form.code.unwrap_or_default(),
                    redirect_uri: form.redirect_uri,
                    client_id,
                    client_secret,
                    client_assertion_type: form.client_assertion_type,
                    client_assertion: form.client_assertion,
                    code_verifier: form.code_verifier,
                })
                .await
        }
        "refresh_token" => {
            ctx.services()
                .oidc_token()
                .exchange_refresh_token(RefreshTokenGrantParams {
                    grant_type: form.grant_type,
                    refresh_token: form.refresh_token.unwrap_or_default(),
                    client_id,
                    client_secret,
                    client_assertion_type: form.client_assertion_type,
                    client_assertion: form.client_assertion,
                })
                .await
        }
        _ => Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType)
            .with_param("grant_type", form.grant_type)),
    };

    match result {
        Ok(response) => {
            let mut response = json_response(StatusCode::OK, response);
            insert_no_store_headers(&mut response);
            Ok(AppResponse(response))
        }
        Err(error) => Err(TokenWebError(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, StatusCode, header::AUTHORIZATION};

    #[test]
    fn token_error_status_for_invalid_grant_is_bad_request() {
        let error = AppError::from_code(TokenErrorCode::RefreshTokenInvalid);
        assert_eq!(token_error_status(&error), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn token_error_status_for_invalid_client_is_unauthorized() {
        let error = AppError::from_code(TokenErrorCode::ClientAuthRequired);
        assert_eq!(token_error_status(&error), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn app_error_to_rfc6749_maps_refresh_errors_to_invalid_grant() {
        let error = AppError::from_code(TokenErrorCode::RefreshTokenInvalid);
        assert_eq!(app_error_to_rfc6749(&error), "invalid_grant");
    }

    #[test]
    fn parse_basic_client_auth_reads_client_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Basic MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOnNlY3JldC0xMjM="
                .parse()
                .unwrap(),
        );

        let parsed = parse_basic_client_auth(&headers).unwrap();
        assert_eq!(parsed.0, "00000000-0000-0000-0000-000000000000");
        assert_eq!(parsed.1, "secret-123");
    }
}
