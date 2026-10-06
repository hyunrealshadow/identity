use std::{borrow::Cow, collections::BTreeMap, str};

use http::{HeaderMap, HeaderValue, StatusCode, header};
use identity_application::{
    error::{
        AppError,
        code::AppErrorCode,
        codes::{common::CommonErrorCode, token::TokenErrorCode},
        kind::ErrorKind,
    },
    openid_connect::{authorize::AuthorizationRequestParams, par::PushedAuthorizationParams},
};
use identity_domain::openid_connect::ClientAssertionType;
use salvo::{
    Depot, Request, Response, Writer, async_trait, handler, handler::HoopedHandler,
    http::ParseError,
};
use serde_json::json;
use url::form_urlencoded::parse;
use urlencoding::decode;

use super::{
    super::{
        client_credentials::parse_basic_client_auth,
        error::Rfc6749Error,
        pipeline::{Endpoint, take},
        token::token_error_code,
    },
    error::authorize_oauth_error_code,
    request::parse_authorize_pairs,
};
use crate::{
    controllers::response::{
        AppResponse, app_state, error_message, insert_no_store_headers, json_response,
    },
    infrastructure::i18n::{error_i18n, resolve_locale_from_headers},
};

pub struct ParWebError {
    error: AppError,
    status: Option<StatusCode>,
}
impl From<AppError> for ParWebError {
    fn from(error: AppError) -> Self {
        Self {
            error,
            status: None,
        }
    }
}
impl Rfc6749Error for ParWebError {
    fn app_error(&self) -> &AppError {
        &self.error
    }

    fn rfc6749_error_code(&self) -> Cow<'static, str> {
        if (23000..24000).contains(&self.error.code()) {
            Cow::Owned(authorize_oauth_error_code(&self.error).to_string())
        } else if self.error.code() == TokenErrorCode::ClientIdInvalid.code() {
            Cow::Borrowed("invalid_client")
        } else {
            Cow::Borrowed(token_error_code(&self.error))
        }
    }

    fn rfc6749_status(&self) -> StatusCode {
        self.status
            .unwrap_or_else(|| match self.rfc6749_error_code().as_ref() {
                "invalid_client" => StatusCode::UNAUTHORIZED,
                _ if self.error.kind() == ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            })
    }
}
#[async_trait]
impl Writer for ParWebError {
    async fn write(self, req: &mut Request, _: &mut Depot, res: &mut Response) {
        let code = self.rfc6749_error_code();
        let status = self.rfc6749_status();
        let description = error_i18n()
            .map(|i18n| {
                error_message(
                    i18n,
                    &resolve_locale_from_headers(req.headers()),
                    &self.error,
                )
            })
            .unwrap_or_else(|| self.error.code().to_string());
        *res = json_response(
            status,
            json!({ "error": code, "error_description": description }),
        );
        insert_no_store_headers(res);
        if status == StatusCode::UNAUTHORIZED && req.headers().contains_key(header::AUTHORIZATION) {
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"par\""),
            );
        }
    }
}

fn parse_pushed_parameters(
    body: &[u8],
    headers: &HeaderMap,
) -> Result<PushedAuthorizationParams, AppError> {
    let encoded =
        str::from_utf8(body).map_err(AppError::map_source(CommonErrorCode::InvalidRequest))?;
    for component in encoded.split(['&', '=']) {
        decode(component).map_err(AppError::map_source(CommonErrorCode::InvalidRequest))?;
    }
    let mut pairs = BTreeMap::<String, String>::new();
    for (key, value) in parse(body) {
        if key != "resource" && pairs.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }
    }
    if pairs.contains_key("request")
        && parse(body).any(|(key, _)| {
            !matches!(
                key.as_ref(),
                "request"
                    | "client_id"
                    | "client_secret"
                    | "client_assertion"
                    | "client_assertion_type"
            )
        })
    {
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
    }
    let basic = parse_basic_client_auth(headers);
    if pairs.contains_key("client_secret")
        && (pairs.contains_key("client_assertion") || pairs.contains_key("client_assertion_type"))
    {
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
    }
    if headers.contains_key(header::AUTHORIZATION) && basic.is_none() {
        return Err(AppError::from_code(TokenErrorCode::ClientAuthRequired));
    }
    if let Some((id, _)) = &basic
        && (pairs.contains_key("client_secret")
            || pairs.contains_key("client_assertion")
            || pairs.contains_key("client_assertion_type")
            || pairs.get("client_id").is_some_and(|value| value != id))
    {
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
    }
    let mut authorization: AuthorizationRequestParams = parse_authorize_pairs(body).into();
    if authorization.request.is_none() && authorization.client_id.is_empty() {
        return Err(AppError::from_code(TokenErrorCode::ClientIdRequired));
    }
    if let Some((id, _)) = &basic {
        authorization.client_id = id.clone();
    }
    let client_assertion_type = pairs
        .get("client_assertion_type")
        .map(|value| {
            value
                .parse::<ClientAssertionType>()
                .map_err(|_| AppError::from_code(TokenErrorCode::ClientAuthRequired))
        })
        .transpose()?;
    let client_secret = basic
        .as_ref()
        .map(|(_, secret)| secret.clone())
        .or_else(|| pairs.get("client_secret").cloned());
    Ok(PushedAuthorizationParams {
        authorization,
        client_secret,
        client_secret_basic: basic.is_some(),
        client_assertion_type,
        client_assertion: pairs.get("client_assertion").cloned(),
    })
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("pushed_authorization")
        .action("parse_request", parse_request)
        .finish("push", par)
}

#[handler]
async fn parse_request(depot: &mut Depot, req: &mut Request) -> Result<(), ParWebError> {
    let headers = req.headers().clone();
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|mime| {
                mime.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        });
    if !is_form {
        return Err(AppError::from_code(CommonErrorCode::InvalidRequest).into());
    }
    let body = req
        .payload_with_max_size(64 * 1024)
        .await
        .map_err(|error| {
            let status = matches!(&error, ParseError::PayloadTooLarge)
                .then_some(StatusCode::PAYLOAD_TOO_LARGE);
            ParWebError {
                error: AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error),
                status,
            }
        })?;
    let params = parse_pushed_parameters(body, &headers)?;
    depot.insert_typed(params);
    Ok(())
}

#[handler]
async fn par(depot: &mut Depot) -> Result<AppResponse, ParWebError> {
    let params: PushedAuthorizationParams = take(depot)?;
    let response = app_state(depot)?
        .services()
        .pushed_authorization()
        .push(params)
        .await?;
    let mut result = json_response(StatusCode::CREATED, response);
    insert_no_store_headers(&mut result);
    Ok(result.into())
}

#[handler]
pub async fn method_not_allowed(res: &mut Response) {
    *res = json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"error":"invalid_request"}),
    );
    res.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("POST, OPTIONS"));
    insert_no_store_headers(res);
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};
    use identity_application::error::codes::authorize::AuthorizeErrorCode;
    use identity_infrastructure::test_app_state_with_mock_settings;
    use salvo::{
        Service,
        affix_state::inject,
        test::{ResponseExt, TestClient},
    };
    use serde_json::{Value, to_value};

    use crate::controllers::oauth2::routes;

    use super::*;

    #[tokio::test]
    async fn par_error_projection_matches_protocol_writer_and_status_overrides() {
        for (source, status_override, expected_code, expected_status) in [
            (
                AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid),
                None,
                "unsupported_response_type",
                StatusCode::BAD_REQUEST,
            ),
            (
                AppError::from_code(AuthorizeErrorCode::RequestUriInvalid),
                None,
                "invalid_request_uri",
                StatusCode::BAD_REQUEST,
            ),
            (
                AppError::from_code(CommonErrorCode::InvalidScope),
                None,
                "invalid_scope",
                StatusCode::BAD_REQUEST,
            ),
            (
                AppError::from_code(TokenErrorCode::ClientIdInvalid),
                None,
                "invalid_client",
                StatusCode::UNAUTHORIZED,
            ),
            (
                AppError::from_code(TokenErrorCode::AssertionVerifyFailed),
                None,
                "invalid_client",
                StatusCode::UNAUTHORIZED,
            ),
            (
                AppError::from_code(TokenErrorCode::RefreshTokenNotFound),
                None,
                "invalid_grant",
                StatusCode::BAD_REQUEST,
            ),
            (
                AppError::from_code(CommonErrorCode::InternalError),
                None,
                "server_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::from_code(CommonErrorCode::InvalidRequest),
                Some(StatusCode::PAYLOAD_TOO_LARGE),
                "invalid_request",
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let error = ParWebError {
                error: source,
                status: status_override,
            };
            assert_eq!(error.rfc6749_error_code(), expected_code);
            assert_eq!(error.rfc6749_status(), expected_status);

            let mut request = TestClient::post("http://localhost/oauth2/par")
                .add_header(header::ACCEPT, "text/html", true)
                .add_header(header::AUTHORIZATION, "Basic YTpzZWNyZXQ=", true)
                .build();
            let mut response = Response::new();
            error
                .write(&mut request, &mut Depot::new(), &mut response)
                .await;

            assert_eq!(response.status_code, Some(expected_status));
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
            assert!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("application/json")
            );
            if expected_status == StatusCode::UNAUTHORIZED {
                assert_eq!(
                    response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                    "Basic realm=\"par\""
                );
            } else {
                assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
            }
            let body: Value = response.take_json().await.unwrap();
            assert_eq!(body["error"], expected_code);
        }
    }

    #[test]
    fn par_form_rejects_ambiguous_credentials_and_mixed_request_objects() {
        let empty = HeaderMap::new();
        for body in [
            "client_id=a&client_id=b",
            "client_id=%FF",
            "client_id=a&client_secret=secret&client_assertion=jwt",
            "client_id=a&request=jwt&scope=openid",
            "client_id=a&request=jwt&resource=urn%3Ax",
        ] {
            assert!(
                parse_pushed_parameters(body.as_bytes(), &empty).is_err(),
                "{body}"
            );
        }
        let parsed = parse_pushed_parameters(
            b"client_id=a&resource=urn%3Ax&resource=urn%3Ay&client_secret=secret",
            &empty,
        )
        .unwrap();
        assert_eq!(parsed.authorization.resources, ["urn:x", "urn:y"]);
        let stored = to_value(parsed.authorization).unwrap();
        assert!(stored.get("client_secret").is_none());
        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YTpzZWNyZXQ="),
        );
        assert!(parse_pushed_parameters(b"client_id=b", &basic).is_err());
        assert!(parse_pushed_parameters(b"response_type=code", &basic).is_err());
        assert!(parse_pushed_parameters(b"request=jwt", &basic).is_ok());
        assert!(parse_pushed_parameters(b"client_id=a&client_secret=secret", &basic).is_err());
    }
    #[tokio::test]
    async fn par_route_returns_protocol_errors_and_enforces_method_and_size() {
        let state = test_app_state_with_mock_settings().await;
        let service = Service::new(routes().hoop(inject(state)));
        for (body, status) in [
            ("client_id=".to_owned(), StatusCode::BAD_REQUEST),
            ("x".repeat(65537), StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let mut response = TestClient::post("http://localhost/oauth2/par")
                .add_header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                    true,
                )
                .text(body)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(status));
            assert!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("no-store")
            );
            let body: Value = response.take_json().await.unwrap();
            assert_eq!(body["error"], "invalid_request");
        }
        let response = TestClient::get("http://localhost/oauth2/par")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
        assert!(response.headers().contains_key(header::ALLOW));
    }
}
