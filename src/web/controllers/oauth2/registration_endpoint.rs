use http::{HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, handler};
use subtle::ConstantTimeEq;
use unic_langid::LanguageIdentifier;

use identity_application::{
    error::{
        AppError, code::AppErrorCode, codes::registration::RegistrationErrorCode, kind::ErrorKind,
    },
    openid_connect::registration::{DynamicClientRegistrationRequest, DynamicClientUpdateRequest},
};

use crate::controllers::response::{
    app_state, error_message, insert_no_store_headers, json_response, parse_json, parse_param,
    render_json,
};
use crate::infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers};
use identity_infrastructure::config::DynamicClientRegistrationConfig;

/// Map a registration `AppError` to an RFC 7591 §3.3 `error` value.
fn registration_rfc_error_code(error: &AppError) -> &'static str {
    match error.code() {
        c if c == RegistrationErrorCode::InvalidRedirectUri.code() => "invalid_redirect_uri",
        c if c == RegistrationErrorCode::InvalidClientMetadata.code() => "invalid_client_metadata",
        c if c == RegistrationErrorCode::InvalidRegistrationAccessToken.code() => "invalid_token",
        _ => match error.kind() {
            ErrorKind::Forbidden => "insufficient_scope",
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
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
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
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\""),
        );
    }
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
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                if status == StatusCode::UNAUTHORIZED {
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static("Bearer error=\"invalid_token\""),
                    );
                }
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
    let registration_config = depot
        .obtain::<DynamicClientRegistrationConfig>()
        .map_err(|_| {
            AppError::from_code(
                identity_application::error::codes::common::CommonErrorCode::InternalError,
            )
        })?;
    validate_initial_access_token(registration_config, ctx.context().is_conformance(), req)?;
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

fn validate_initial_access_token(
    config: &DynamicClientRegistrationConfig,
    is_conformance: bool,
    req: &Request,
) -> Result<(), AppError> {
    let provided = bearer_token(req).ok();
    if initial_access_token_matches(config, is_conformance, provided) {
        Ok(())
    } else {
        Err(AppError::from_code(
            RegistrationErrorCode::InvalidRegistrationAccessToken,
        ))
    }
}

fn initial_access_token_matches(
    config: &DynamicClientRegistrationConfig,
    is_conformance: bool,
    provided: Option<&str>,
) -> bool {
    if !is_conformance {
        return true;
    }
    let Some(expected) = config.required_conformance_initial_access_token() else {
        return true;
    };
    let Some(provided) = provided else {
        return false;
    };

    expected.len() == provided.len() && bool::from(expected.as_bytes().ct_eq(provided.as_bytes()))
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
pub async fn update(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), RegistrationWebError> {
    let ctx = app_state(depot)?;
    let client_id: String = parse_param(req, "client_id")?;
    let token = bearer_token(req)?.to_owned();
    // Authenticate before parsing metadata or reporting validation errors.
    ctx.services()
        .dynamic_client_registration()
        .read(&client_id, &token, &ctx.services().oidc().issuer()?)
        .await?;
    let request: DynamicClientUpdateRequest = parse_json(req).await?;
    let response = ctx
        .services()
        .dynamic_client_registration()
        .update(
            &client_id,
            &token,
            request,
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

#[cfg(test)]
mod tests {
    use super::initial_access_token_matches;
    use identity_infrastructure::config::DynamicClientRegistrationConfig;

    #[cfg(feature = "oidc-conformance")]
    fn registration_config(initial_access_token: Option<&str>) -> DynamicClientRegistrationConfig {
        DynamicClientRegistrationConfig {
            conformance_initial_access_token: initial_access_token.map(str::to_owned),
        }
    }

    #[cfg(not(feature = "oidc-conformance"))]
    fn registration_config(_initial_access_token: Option<&str>) -> DynamicClientRegistrationConfig {
        DynamicClientRegistrationConfig::default()
    }

    #[test]
    #[cfg(feature = "oidc-conformance")]
    fn registration_is_open_when_conformance_initial_access_token_is_not_configured() {
        assert!(initial_access_token_matches(
            &registration_config(None),
            true,
            None
        ));
        assert!(initial_access_token_matches(
            &registration_config(Some("   ")),
            true,
            None
        ));
    }

    #[test]
    fn fixed_initial_access_token_is_ignored_outside_conformance() {
        let config = registration_config(Some("registration-secret"));

        assert!(initial_access_token_matches(&config, false, None));
        assert!(initial_access_token_matches(
            &config,
            false,
            Some("wrong-secret")
        ));
    }

    #[test]
    #[cfg(feature = "oidc-conformance")]
    fn conformance_requires_the_exact_configured_initial_access_token() {
        let config = registration_config(Some("registration-secret"));

        assert!(initial_access_token_matches(
            &config,
            true,
            Some("registration-secret")
        ));
        assert!(!initial_access_token_matches(&config, true, None));
        assert!(!initial_access_token_matches(
            &config,
            true,
            Some("wrong-secret")
        ));
    }
}
#[cfg(test)]
mod update_route_tests {
    use http::{StatusCode, header};
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };
    #[tokio::test]
    async fn update_route_requires_bearer_auth_and_supports_put_preflight() {
        let state =
            identity_infrastructure::test_app_state_with_cors_origin(Some("http://localhost:3000"))
                .await;
        let service = Service::new(
            crate::controllers::oauth2::routes().hoop(salvo::affix_state::inject(state)),
        );
        let url = "http://127.0.0.1:5800/oauth2/register/11111111-1111-1111-1111-111111111111";
        let mut response = TestClient::put(url)
            .json(&serde_json::json!({"client_id":"11111111-1111-1111-1111-111111111111"}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer error=\"invalid_token\""
        );
        let json: serde_json::Value =
            serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(json["error"], "invalid_token");
        let response = TestClient::options(url)
            .add_header(header::ORIGIN, "http://localhost:3000", true)
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT", true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NO_CONTENT));
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("PUT")
        );
    }
}
