use std::error::Error as _;

use http::StatusCode;
use salvo::{Depot, Request, Router, handler};
use serde::{Deserialize, Serialize};

use crate::{
    application::{install::InstallInput, setting::runtime::SettingProvider},
    domain::key::AsymmetricKeyAlgorithm,
    web::controllers::response::{
        AppResponse, JsonWebError, JsonWebResult, app_state, json_response, parse_json,
    },
};

pub fn routes() -> Router {
    Router::with_path("install").post(install_submit)
}

#[derive(Debug, Deserialize)]
struct InstallRequest {
    username: String,
    email: String,
    password: String,
    domain: String,
    key_algorithm: String,
}

#[derive(Debug, Serialize)]
struct InstallResponse {
    status: &'static str,
    restart_required: bool,
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
async fn install_submit(depot: &mut Depot, req: &mut Request) -> JsonWebResult<AppResponse> {
    let ctx = app_state(depot).map_err(JsonWebError)?;
    let request: InstallRequest = parse_json(req).await.map_err(JsonWebError)?;

    if *ctx.settings().installation_initialized().current_value() {
        return Err(identity_application::error::AppError::from_code(
            identity_application::error::codes::install::InstallErrorCode::AlreadyInitialized,
        )
        .into());
    }

    let input = InstallInput {
        username: request.username.clone(),
        email: request.email.clone(),
        password: request.password.clone(),
        domain: request.domain.clone(),
        key_algorithm: parse_algorithm(&request.key_algorithm)?,
    };

    if let Err(error) = ctx.services().install().install(input).await {
        log_install_failure(&error, &request);
        return Err(error.into());
    }

    ctx.lifecycle().request_shutdown();
    Ok(json_response(
        StatusCode::ACCEPTED,
        InstallResponse {
            status: "installed",
            restart_required: true,
        },
    )
    .into())
}

fn parse_algorithm(value: &str) -> Result<AsymmetricKeyAlgorithm, JsonWebError> {
    match value {
        "ecdsa-p256" => Ok(AsymmetricKeyAlgorithm::EcdsaP256),
        "ecdsa-p384" => Ok(AsymmetricKeyAlgorithm::EcdsaP384),
        "ecdsa-p521" => Ok(AsymmetricKeyAlgorithm::EcdsaP521),
        "ecdsa-secp256k1" => Ok(AsymmetricKeyAlgorithm::EcdsaSecp256k1),
        "ed25519" => Ok(AsymmetricKeyAlgorithm::Ed25519),
        "ed448" => Ok(AsymmetricKeyAlgorithm::Ed448),
        "rsa-2048" => Ok(AsymmetricKeyAlgorithm::Rsa { bits: 2048 }),
        "rsa-3072" => Ok(AsymmetricKeyAlgorithm::Rsa { bits: 3072 }),
        "rsa-4096" => Ok(AsymmetricKeyAlgorithm::Rsa { bits: 4096 }),
        _ => Err(identity_application::error::AppError::from_code(
            identity_application::error::codes::install::InstallErrorCode::UnsupportedAlgorithm,
        )
        .with_param("algorithm", value)
        .into()),
    }
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
            key_algorithm: "ed25519".to_owned(),
        };
        let error = AppError::from_code(CommonErrorCode::InternalError);

        let context = InstallFailureLogContext::from_request(&request);

        assert!(should_log_install_failure_as_error(&error));
        assert_eq!(context.domain, "identity.example.com");
        assert_eq!(context.key_algorithm, "ed25519");
    }
}
