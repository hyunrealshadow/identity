use super::{
    authorize_endpoint::{authorize_oauth_error_code, parse_authorize_pairs},
    token_endpoint::{app_error_to_rfc6749, parse_basic_client_auth, token_error_status},
};
use crate::controllers::response::{
    AppResponse, app_state, error_message, insert_no_store_headers, json_response,
};
use crate::infrastructure::i18n::{error_i18n, resolve_locale_from_headers};
use http::{StatusCode, header};
use identity_application::{
    error::{
        AppError,
        code::AppErrorCode,
        codes::{common::CommonErrorCode, token::TokenErrorCode},
    },
    openid_connect::{authorize::AuthorizationRequestParams, par::PushedAuthorizationParams},
};
use identity_domain::openid_connect::ClientAssertionType;
use salvo::{Depot, Request, Response, Writer, async_trait, handler};

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
fn par_error_code(error: &AppError) -> String {
    if (23000..24000).contains(&error.code()) {
        authorize_oauth_error_code(error).to_string()
    } else if error.code() == TokenErrorCode::ClientIdInvalid.code() {
        "invalid_client".to_owned()
    } else {
        app_error_to_rfc6749(error).to_owned()
    }
}
#[async_trait]
impl Writer for ParWebError {
    async fn write(self, req: &mut Request, _: &mut Depot, res: &mut Response) {
        let code = par_error_code(&self.error);
        let status = self.status.unwrap_or_else(|| {
            if code == "invalid_client" {
                StatusCode::UNAUTHORIZED
            } else {
                token_error_status(&self.error)
            }
        });
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
            serde_json::json!({ "error": code, "error_description": description }),
        );
        insert_no_store_headers(res);
        if status == StatusCode::UNAUTHORIZED && req.headers().contains_key(header::AUTHORIZATION) {
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Basic realm=\"par\""),
            );
        }
    }
}

fn parse_pushed_parameters(
    body: &[u8],
    headers: &http::HeaderMap,
) -> Result<PushedAuthorizationParams, AppError> {
    let encoded = std::str::from_utf8(body)
        .map_err(|error| AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error))?;
    for component in encoded.split(['&', '=']) {
        urlencoding::decode(component).map_err(|error| {
            AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error)
        })?;
    }
    let mut pairs = std::collections::BTreeMap::<String, String>::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        if key != "resource" && pairs.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }
    }
    if pairs.contains_key("request")
        && url::form_urlencoded::parse(body).any(|(key, _)| {
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
    if let Some((id, _)) = &basic {
        if pairs.contains_key("client_secret")
            || pairs.contains_key("client_assertion")
            || pairs.contains_key("client_assertion_type")
            || pairs.get("client_id").is_some_and(|value| value != id)
        {
            return Err(AppError::from_code(CommonErrorCode::InvalidRequest));
        }
    }
    let mut authorization: AuthorizationRequestParams = parse_authorize_pairs(body).into();
    if authorization.request.is_none() && authorization.client_id.is_empty() {
        return Err(AppError::from_code(TokenErrorCode::ClientIdRequired));
    }
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

#[handler]
pub async fn par(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, ParWebError> {
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
            let status = matches!(&error, salvo::http::ParseError::PayloadTooLarge)
                .then_some(StatusCode::PAYLOAD_TOO_LARGE);
            ParWebError {
                error: AppError::from_code(CommonErrorCode::InvalidRequest).with_source(error),
                status,
            }
        })?;
    let params = parse_pushed_parameters(body, &headers)?;
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
        serde_json::json!({"error":"invalid_request"}),
    );
    res.headers_mut().insert(
        header::ALLOW,
        http::HeaderValue::from_static("POST, OPTIONS"),
    );
    insert_no_store_headers(res);
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };
    #[test]
    fn par_form_rejects_ambiguous_credentials_and_mixed_request_objects() {
        let empty = http::HeaderMap::new();
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
        let stored = serde_json::to_value(parsed.authorization).unwrap();
        assert!(stored.get("client_secret").is_none());
        let mut basic = http::HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            http::HeaderValue::from_static("Basic YTpzZWNyZXQ="),
        );
        assert!(parse_pushed_parameters(b"client_id=b", &basic).is_err());
        assert!(parse_pushed_parameters(b"response_type=code", &basic).is_err());
        assert!(parse_pushed_parameters(b"request=jwt", &basic).is_ok());
        assert!(parse_pushed_parameters(b"response_type=code", &basic).is_err());
        assert!(parse_pushed_parameters(b"request=jwt", &basic).is_ok());
        assert!(parse_pushed_parameters(b"client_id=a&client_secret=secret", &basic).is_err());
    }
    #[tokio::test]
    async fn par_route_returns_protocol_errors_and_enforces_method_and_size() {
        let state = identity_infrastructure::test_app_state_with_mock_settings().await;
        let service = Service::new(super::super::routes().hoop(salvo::affix_state::inject(state)));
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
            let body: serde_json::Value = response.take_json().await.unwrap();
            assert_eq!(body["error"], "invalid_request");
        }
        let response = TestClient::get("http://localhost/oauth2/par")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
        assert!(response.headers().contains_key(header::ALLOW));
    }
}
