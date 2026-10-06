use http::StatusCode;
use identity_application::{
    error::{
        AppError,
        code::AppErrorCode,
        codes::{
            common::CommonErrorCode, device::DeviceAuthorizationErrorCode, token::TokenErrorCode,
        },
        kind::ErrorKind,
    },
    openid_connect::device::DeviceAuthorizationParams,
};
use salvo::{Depot, Request, Response, Writer, async_trait, handler, handler::HoopedHandler};
use serde::{Deserialize, Serialize};
use unic_langid::LanguageIdentifier;

use super::super::{
    client_credentials::ClientCredentials,
    pipeline::{Endpoint, Extract, RequireState, take},
};
use crate::{
    controllers::response::{
        AppResponse, app_state, error_message, insert_no_store_headers, json_response,
        log_app_error,
    },
    infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers},
};

/// RFC 8628 §3.2 request: a form POST carrying the client's credentials and an
/// optional scope.
#[derive(Debug, Deserialize)]
struct DeviceAuthorizationForm {
    #[serde(default, rename = "resource")]
    resources: Vec<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceAuthorizationErrorResponse {
    error: &'static str,
    error_description: String,
}

/// Map a device authorization `AppError` to an RFC 6749 §5.2 `error` value.
///
/// `unsupported_grant_type` is deliberately absent: the endpoint exists, so a
/// client that is not allowed to use the device grant is told
/// `unauthorized_client` instead.
fn device_error_code(error: &AppError) -> &'static str {
    let code = error.code();
    if code == CommonErrorCode::InvalidScope.code() {
        return "invalid_scope";
    }
    if code == CommonErrorCode::InvalidTarget.code() {
        return "invalid_target";
    }

    if code == DeviceAuthorizationErrorCode::GrantNotAllowed.code() {
        return "unauthorized_client";
    }
    if code == TokenErrorCode::ClientIdRequired.code() {
        // A missing parameter is an invalid request; only a failed
        // authentication is an invalid client (RFC 6749 §5.2).
        return "invalid_request";
    }
    if code == DeviceAuthorizationErrorCode::ScopeInvalid.code()
        || code == DeviceAuthorizationErrorCode::ScopeNotAssignedToClient.code()
    {
        return "invalid_scope";
    }
    // Client authentication failures keep their token-endpoint semantics.
    if [
        TokenErrorCode::ClientNotFound,
        TokenErrorCode::ClientIdInvalid,
        TokenErrorCode::ClientCredentialsInvalid,
        TokenErrorCode::ClientAuthRequired,
        TokenErrorCode::AssertionVerifyFailed,
        TokenErrorCode::AssertionExpired,
        TokenErrorCode::AssertionAudMismatch,
        TokenErrorCode::AssertionIssSubMismatch,
    ]
    .iter()
    .any(|candidate| code == candidate.code())
    {
        return "invalid_client";
    }

    match error.kind() {
        ErrorKind::Validation | ErrorKind::Gone | ErrorKind::Conflict => "invalid_request",
        _ => "server_error",
    }
}

fn device_error_status(error: &AppError) -> StatusCode {
    match error.kind() {
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        _ if device_error_code(error) == "invalid_client" => StatusCode::UNAUTHORIZED,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn device_error_response(error: AppError, i18n: &I18n, locale: &LanguageIdentifier) -> Response {
    let status = device_error_status(&error);
    let body = DeviceAuthorizationErrorResponse {
        error: device_error_code(&error),
        error_description: error_message(i18n, locale, &error),
    };

    let mut response = json_response(status, body);
    insert_no_store_headers(&mut response);
    response
}

/// Device authorization endpoint error wrapper.
///
/// Always answers with RFC 6749 §5.2 JSON (`{ "error", "error_description" }`)
/// and the matching status code, independent of the `Accept` header.
pub struct DeviceAuthorizationWebError(pub AppError);

impl From<AppError> for DeviceAuthorizationWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for DeviceAuthorizationWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        log_app_error(&self.0, "device authorization request failed");
        match error_i18n() {
            Some(i18n) => {
                let locale = resolve_locale_from_headers(req.headers());
                *res = device_error_response(self.0, i18n, &locale);
            }
            None => {
                let status = device_error_status(&self.0);
                let body = DeviceAuthorizationErrorResponse {
                    error: device_error_code(&self.0),
                    error_description: self.0.code().to_string(),
                };
                let mut response = json_response(status, body);
                insert_no_store_headers(&mut response);
                *res = response;
            }
        }
    }
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("device_authorization")
        .action("state", RequireState::<DeviceAuthorizationWebError>::new())
        .action(
            "parse_form",
            Extract::<DeviceAuthorizationForm, DeviceAuthorizationWebError>::form(),
        )
        .action("prepare_credentials", prepare_credentials)
        .finish("authorize", device_authorization)
}

#[handler]
async fn prepare_credentials(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<(), DeviceAuthorizationWebError> {
    let form: DeviceAuthorizationForm = take(depot)?;
    let credentials = ClientCredentials::resolve(
        req.headers(),
        form.client_id,
        form.client_secret,
        form.client_assertion_type,
    )?;
    depot.insert_typed(DeviceAuthorizationParams {
        resources: form.resources,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        client_secret_basic: credentials.basic,
        client_assertion_type: credentials.assertion_type,
        client_assertion: form.client_assertion,
        scope: form.scope,
    });
    Ok(())
}

#[handler]
async fn device_authorization(
    depot: &mut Depot,
) -> Result<AppResponse, DeviceAuthorizationWebError> {
    let ctx = app_state(depot)?;
    let response = ctx
        .services()
        .oidc_device_authorization()
        .authorize(take(depot)?)
        .await?;
    let mut response = json_response(StatusCode::OK, response);
    insert_no_store_headers(&mut response);
    Ok(AppResponse(response))
}

#[cfg(test)]
mod tests {
    use http::header;
    use identity_infrastructure::test_app_state_with_mock_settings;
    use salvo::{
        Response, Service,
        affix_state::inject,
        test::{ResponseExt, TestClient},
    };

    use crate::controllers::oauth2::routes;

    use super::*;

    async fn post_device_authorization(body: String) -> Response {
        let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
        let service = Service::new(app);

        TestClient::post("http://127.0.0.1:5800/oauth2/device")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body(body)
            .send(&service)
            .await
    }

    #[tokio::test]
    async fn device_authorization_route_requires_client_id() {
        let mut response = post_device_authorization("scope=openid".to_owned()).await;

        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = response.take_string().await.unwrap();
        assert!(body.contains("\"invalid_request\""), "{body}");
    }

    #[test]
    fn missing_client_id_is_an_invalid_request() {
        // Client identifier resolution is shared with the token endpoint, so
        // the missing parameter reports the token endpoint's error code.
        let error = AppError::from_code(TokenErrorCode::ClientIdRequired);

        assert_eq!(device_error_code(&error), "invalid_request");
        assert_eq!(device_error_status(&error), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_client_without_the_device_grant_is_unauthorized_not_unsupported() {
        let error = AppError::from_code(DeviceAuthorizationErrorCode::GrantNotAllowed);

        assert_eq!(device_error_code(&error), "unauthorized_client");
        assert_eq!(device_error_status(&error), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn scope_failures_use_invalid_scope() {
        for code in [
            DeviceAuthorizationErrorCode::ScopeInvalid,
            DeviceAuthorizationErrorCode::ScopeNotAssignedToClient,
        ] {
            let error = AppError::from_code(code);
            assert_eq!(device_error_code(&error), "invalid_scope", "{code:?}");
            assert_eq!(device_error_status(&error), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn client_authentication_failures_are_invalid_client() {
        let error = AppError::from_code(TokenErrorCode::ClientAuthRequired);

        assert_eq!(device_error_code(&error), "invalid_client");
        assert_eq!(device_error_status(&error), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn internal_failures_are_server_errors() {
        let error = AppError::from_code(DeviceAuthorizationErrorCode::StoreRequestFailed);

        assert_eq!(device_error_code(&error), "server_error");
        assert_eq!(
            device_error_status(&error),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
