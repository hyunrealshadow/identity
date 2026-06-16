use http::{HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, handler};
use unic_langid::LanguageIdentifier;

use identity_application::{
    error::{
        AppError, code::AppErrorCode, codes::registration::RegistrationErrorCode,
        kind::ErrorKind,
    },
    openid_connect::registration::DynamicClientRegistrationRequest,
};

use crate::controllers::response::{
    app_state, error_message, insert_no_store_headers, json_response, parse_json, parse_param,
    render_json,
};
use crate::infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers};

/// Map a registration `AppError` to an RFC 7591 §3.3 `error` value.
fn registration_rfc_error_code(error: &AppError) -> &'static str {
    match error.code() {
        c if c == RegistrationErrorCode::InvalidRedirectUri.code() => "invalid_redirect_uri",
        c if c == RegistrationErrorCode::InvalidClientMetadata.code() => "invalid_client_metadata",
        c if c == RegistrationErrorCode::InvalidRegistrationAccessToken.code() => {
            "invalid_token"
        }
        _ => match error.kind() {
            ErrorKind::Unauthorized => "invalid_token",
            ErrorKind::Validation => "invalid_client_metadata",
            _ => "server_error",
        },
    }
}

fn registration_error_status(error: &AppError) -> StatusCode {
    match error.kind() {
        ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        // All registration validation errors are 400 per RFC 7591.
        _ => StatusCode::BAD_REQUEST,
    }
}

/// Build the RFC 7591 §3.3 registration error response body. The
/// `error_description` is resolved through Fluent using `locale`, keeping the
/// message both localized and specific to the underlying error code.
fn registration_error_response(
    error: AppError,
    i18n: &I18n,
    locale: &LanguageIdentifier,
) -> Response {
    let rfc_error = registration_rfc_error_code(&error);
    let description = error_message(i18n, locale, &error);
    let status = registration_error_status(&error);

    let error_body = serde_json::json!({
        "error": rfc_error,
        "error_description": description
    });

    let mut response = json_response(status, error_body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Dynamic client registration endpoint error wrapper.
///
/// Always renders RFC 7591 §3.3 JSON (`{ "error", "error_description" }`),
/// regardless of the `Accept` header. The `error_description` is localized via
/// Fluent using the request's `Accept-Language`.
pub struct RegistrationWebError(pub AppError);

impl From<AppError> for RegistrationWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

#[async_trait]
impl Writer for RegistrationWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        match error_i18n() {
            Some(i18n) => {
                let locale = resolve_locale_from_headers(req.headers());
                *res = registration_error_response(self.0, i18n, &locale);
            }
            None => {
                let rfc_error = registration_rfc_error_code(&self.0);
                let status = registration_error_status(&self.0);
                let error_body = serde_json::json!({
                    "error": rfc_error,
                    "error_description": self.0.code().to_string()
                });
                let mut response = json_response(status, error_body);
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                );
                *res = response;
            }
        }
    }
}

#[handler]
pub async fn register(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), RegistrationWebError> {
    let ctx = app_state(depot)?;
    let request: DynamicClientRegistrationRequest = parse_json(req).await?;
    let response = ctx
        .services()
        .dynamic_client_registration()
        .register(request, &ctx.services().oidc().issuer()?)
        .await?;

    insert_no_store_headers(res);
    render_json(res, StatusCode::CREATED, response);
    Ok(())
}

#[handler]
pub async fn read(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), RegistrationWebError> {
    let ctx = app_state(depot)?;
    let client_id: String = parse_param(req, "client_id")?;
    let registration_access_token = bearer_token(req)?;
    let response = ctx
        .services()
        .dynamic_client_registration()
        .read(
            &client_id,
            registration_access_token,
            &ctx.services().oidc().issuer()?,
        )
        .await?;

    insert_no_store_headers(res);
    render_json(res, StatusCode::OK, response);
    Ok(())
}

#[handler]
pub async fn delete(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), RegistrationWebError> {
    let ctx = app_state(depot)?;
    let client_id: String = parse_param(req, "client_id")?;
    let registration_access_token = bearer_token(req)?;
    ctx.services()
        .dynamic_client_registration()
        .delete(&client_id, registration_access_token)
        .await?;

    insert_no_store_headers(res);
    render_json(res, StatusCode::NO_CONTENT, ());
    Ok(())
}

fn bearer_token(req: &Request) -> Result<&str, AppError> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::from_code(
                identity_application::error::codes::registration::RegistrationErrorCode::InvalidRegistrationAccessToken,
            )
        })
}
