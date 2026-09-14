use std::error::Error as _;

use http::StatusCode;
use salvo::{Depot, Request, Router, handler};
use serde::{Deserialize, Serialize};

use crate::{
    application::install::InstallInput,
    web::controllers::response::{
        AppResponse, JsonWebError, JsonWebResult, app_state, insert_no_store_headers,
        json_response, parse_json,
    },
};

pub fn routes() -> Router {
    Router::with_path("installation").post(install_submit)
}

pub fn status_routes() -> Router {
    Router::with_path("installation/status").get(installation_status)
}

#[derive(Debug, Serialize)]
struct InstallationStatusResponse {
    installed: bool,
}

#[derive(Debug, Deserialize)]
struct InstallRequest {
    username: String,
    email: String,
    password: String,
    domain: String,
    application_url: String,
    key_algorithm: String,
}

#[derive(Debug, Serialize)]
struct InstallResponse {
    status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallFailureLogContext {
    domain: String,
    key_algorithm: String,
}

impl InstallFailureLogContext {
    fn from_request(request: &InstallRequest) -> Self {
        Self {
            domain: request.domain.clone(),
            key_algorithm: request.key_algorithm.clone(),
        }
    }
}

fn should_log_install_failure_as_error(error: &identity_application::error::AppError) -> bool {
    error.kind().http_status().is_server_error()
}

fn log_install_failure(error: &identity_application::error::AppError, request: &InstallRequest) {
    let context = InstallFailureLogContext::from_request(request);

    if should_log_install_failure_as_error(error) {
        tracing::error!(
            error = %error,
            source = ?error.source(),
            code = error.code(),
            domain = %context.domain,
            key_algorithm = %context.key_algorithm,
            "install submission failed"
        );
    } else {
        tracing::warn!(
            error = %error,
            code = error.code(),
            domain = %context.domain,
            key_algorithm = %context.key_algorithm,
            "install submission rejected"
        );
    }
}

#[handler]
async fn installation_status(depot: &mut Depot) -> JsonWebResult<AppResponse> {
    let ctx = app_state(depot).map_err(JsonWebError)?;
    let mut response = json_response(
        StatusCode::OK,
        InstallationStatusResponse {
            installed: ctx.services().install().is_initialized(),
        },
    );
    insert_no_store_headers(&mut response);
    Ok(response.into())
}

#[handler]
async fn install_submit(depot: &mut Depot, req: &mut Request) -> JsonWebResult<AppResponse> {
    let ctx = app_state(depot).map_err(JsonWebError)?;
    let request: InstallRequest = parse_json(req).await.map_err(JsonWebError)?;

    // Everything else — the already-initialized guard and the algorithm name —
    // belongs to the installation use case, not to the transport.
    let input = InstallInput {
        username: request.username.clone(),
        email: request.email.clone(),
        password: request.password.clone(),
        domain: request.domain.clone(),
        application_url: request.application_url.clone(),
        key_algorithm: request.key_algorithm.clone(),
    };

    ctx.services()
        .install()
        .install(input)
        .await
        .map_err(|error| {
            log_install_failure(&error, &request);
            JsonWebError(error)
        })?;

    let mut response = json_response(
        StatusCode::CREATED,
        InstallResponse {
            status: "installed",
        },
    );
    insert_no_store_headers(&mut response);
    Ok(response.into())
}

#[cfg(test)]
mod tests {
    use identity_application::error::{AppError, codes::common::CommonErrorCode};

    use super::{InstallFailureLogContext, InstallRequest, should_log_install_failure_as_error};

    #[test]
    fn internal_install_errors_are_logged_with_sanitized_context() {
        let request = InstallRequest {
            username: "admin".to_owned(),
            email: "admin@example.com".to_owned(),
            password: "super-secret-password".to_owned(),
            domain: "identity.example.com".to_owned(),
            application_url: "https://login.example.com".to_owned(),
            key_algorithm: "ed25519".to_owned(),
        };
        let error = AppError::from_code(CommonErrorCode::InternalError);

        let context = InstallFailureLogContext::from_request(&request);

        assert!(should_log_install_failure_as_error(&error));
        assert_eq!(context.domain, "identity.example.com");
        assert_eq!(context.key_algorithm, "ed25519");
    }
}
