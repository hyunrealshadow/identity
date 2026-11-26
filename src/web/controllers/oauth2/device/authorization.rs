use crate::error::{error_message, log_app_error, with_request_catalog};
use http::StatusCode;
use identity_application::{
    error::{
        AppError, ErrorCode,
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
    token::is_client_auth_token_error,
};
use crate::{
    controllers::response::{AppResponse, app_state, insert_no_store_headers, json_response},
    infrastructure::i18n::I18n,
};

/// RFC 8628 搂3.2 request: a form POST carrying the client's credentials and an
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

fn device_code_to_rfc6749(code: DeviceAuthorizationErrorCode) -> &'static str {
    match code {
        DeviceAuthorizationErrorCode::GrantNotAllowed => "unauthorized_client",
        DeviceAuthorizationErrorCode::ScopeInvalid
        | DeviceAuthorizationErrorCode::ScopeNotAssignedToClient => "invalid_scope",
        DeviceAuthorizationErrorCode::UserCodeUnavailable
        | DeviceAuthorizationErrorCode::CodeGenerationFailed
        | DeviceAuthorizationErrorCode::StoreRequestFailed
        | DeviceAuthorizationErrorCode::IssuerInvalid
        | DeviceAuthorizationErrorCode::LoginDomainInvalid
        | DeviceAuthorizationErrorCode::LoadRequestFailed
        | DeviceAuthorizationErrorCode::DeserializeRequestFailed
        | DeviceAuthorizationErrorCode::InvalidAuthorizationState
        | DeviceAuthorizationErrorCode::StoreDecisionFailed
        | DeviceAuthorizationErrorCode::UserLookupFailed
        | DeviceAuthorizationErrorCode::ClientLookupFailed => "server_error",
        DeviceAuthorizationErrorCode::UserCodeNotFound
        | DeviceAuthorizationErrorCode::RequestAlreadyDecided
        | DeviceAuthorizationErrorCode::ClientNotFound
        | DeviceAuthorizationErrorCode::UserNotFound
        | DeviceAuthorizationErrorCode::RequestExpired
        | DeviceAuthorizationErrorCode::VerificationLoginRequired => "invalid_request",
    }
}

/// Map a device authorization `AppError` to an RFC 6749 §5.2 `error` value.
///
/// `unsupported_grant_type` is deliberately absent: the endpoint exists, so a
/// client that is not allowed to use the device grant is told
/// `unauthorized_client` instead.
fn device_error_code(error: &AppError) -> &'static str {
    match error.error_code() {
        ErrorCode::Common(CommonErrorCode::InvalidScope) => "invalid_scope",
        ErrorCode::Common(CommonErrorCode::InvalidTarget) => "invalid_target",
        ErrorCode::Device(code) => device_code_to_rfc6749(code),
        // Missing client_id is invalid_request; client authentication failures keep invalid_client.
        ErrorCode::Token(TokenErrorCode::ClientIdRequired) => "invalid_request",
        ErrorCode::Token(code) if is_client_auth_token_error(code) => "invalid_client",
        _ => match error.kind() {
            ErrorKind::Validation | ErrorKind::Gone | ErrorKind::Conflict => "invalid_request",
            _ => "server_error",
        },
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
/// Always answers with RFC 6749 搂5.2 JSON (`{ "error", "error_description" }`)
/// and the matching status code, independent of the `Accept` header.
pub struct DeviceAuthorizationWebError(pub AppError);

impl From<AppError> for DeviceAuthorizationWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for DeviceAuthorizationWebError {
    async fn write(self, req: &mut Request, depot: &mut Depot, res: &mut Response) {
        log_app_error(&self.0, "device authorization request failed");
        *res = with_request_catalog(depot, req.headers(), |i18n, locale| {
            device_error_response(self.0, i18n, locale)
        });
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

    use super::*;
    use identity_application::error::codes::{device, token};

    #[test]
    fn missing_client_id_is_an_invalid_request() {
        // Client identifier resolution is shared with the token endpoint, so
        // the missing parameter reports the token endpoint's error code.
        let error: AppError = token::error::ClientIdRequired.into();

        assert_eq!(device_error_code(&error), "invalid_request");
        assert_eq!(device_error_status(&error), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_client_without_the_device_grant_is_unauthorized_not_unsupported() {
        let error: AppError = device::error::GrantNotAllowed.into();

        assert_eq!(device_error_code(&error), "unauthorized_client");
        assert_eq!(device_error_status(&error), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn scope_failures_use_invalid_scope() {
        for error in [
            device::error::ScopeInvalid.into_error(),
            device::error::ScopeNotAssignedToClient.into_error(),
        ] {
            let code = error.code();
            assert_eq!(device_error_code(&error), "invalid_scope", "{code}");
            assert_eq!(device_error_status(&error), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn client_authentication_failures_are_invalid_client() {
        let error: AppError = token::error::ClientAuthRequired.into();

        assert_eq!(device_error_code(&error), "invalid_client");
        assert_eq!(device_error_status(&error), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn internal_failures_are_server_errors() {
        let error: AppError = device::error::StoreRequestFailed.into();

        assert_eq!(device_error_code(&error), "server_error");
        assert_eq!(
            device_error_status(&error),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
