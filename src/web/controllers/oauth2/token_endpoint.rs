use axum::{
    extract::{Form, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{
    application::{
        error::{AppError, code::AppErrorCode, codes::token::TokenErrorCode, kind::ErrorKind},
        openid_connect::token::{AuthorizationCodeGrantParams, RefreshTokenGrantParams},
    },
    boot::AppState,
};

use super::super::response::AppJson;

#[derive(Debug, Deserialize)]
pub(crate) struct TokenForm {
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

fn token_error_response(error: AppError) -> Response {
    let status = if error.kind() == ErrorKind::Internal {
        StatusCode::INTERNAL_SERVER_ERROR
    } else if app_error_to_rfc6749(&error) == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };

    let rfc_error = app_error_to_rfc6749(&error);
    let body = TokenErrorResponse {
        error: rfc_error,
        error_description: format!("error code {}", error.code()),
    };

    let mut response = (status, axum::Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );
    response
}

fn parse_basic_client_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;
    Some((client_id.to_string(), client_secret.to_string()))
}

#[axum::debug_handler]
pub async fn token(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
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
        _ => Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType)),
    };

    match result {
        Ok(response) => {
            let mut response = AppJson(response).into_response();
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            response.headers_mut().insert(
                axum::http::header::PRAGMA,
                HeaderValue::from_static("no-cache"),
            );
            response
        }
        Err(error) => token_error_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};

    #[test]
    fn token_error_response_sets_cache_headers() {
        let response = token_error_response(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            HeaderValue::from_static("no-store")
        );
        assert_eq!(
            response.headers().get("pragma").unwrap(),
            HeaderValue::from_static("no-cache")
        );
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
