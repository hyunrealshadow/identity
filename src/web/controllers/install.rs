use std::error::Error as _;

use http::{HeaderMap, StatusCode};
use salvo::{Depot, Request, Response, Router, handler};
use serde::Deserialize;

use super::{
    response::{WebResult, app_state, parse_form, redirect_to, render_app_error, render_html},
    shared::{csrf_middleware, csrf_token},
};
use crate::{
    application::{install::InstallInput, setting::runtime::SettingProvider},
    boot::AppState,
    domain::key::AsymmetricKeyAlgorithm,
    infrastructure::{i18n::resolve_locale_from_headers, web},
    web::views::install::{InstallAlgorithmOption, InstallPageData},
};

pub fn routes() -> Router {
    Router::with_path("install")
        .hoop(csrf_middleware())
        .get(install_page)
        .post(install_submit)
}

#[derive(Debug, Deserialize)]
struct InstallForm {
    username: String,
    email: String,
    password: String,
    domain: String,
    key_algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallFailureLogContext {
    domain: String,
    key_algorithm: String,
}

impl InstallFailureLogContext {
    fn from_form(form: &InstallForm) -> Self {
        Self {
            domain: form.domain.clone(),
            key_algorithm: form.key_algorithm.clone(),
        }
    }
}

fn should_log_install_failure_as_error(error: &identity_application::error::AppError) -> bool {
    error.kind().http_status().is_server_error()
}

fn log_install_failure(error: &identity_application::error::AppError, form: &InstallForm) {
    let context = InstallFailureLogContext::from_form(form);

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

struct InstallPageRenderInput<'a> {
    ctx: &'a AppState,
    headers: &'a HeaderMap,
    csrf_token: String,
    username: String,
    email: String,
    domain: String,
    selected_algorithm: &'a str,
    error: Option<String>,
}

fn render_install_page(input: InstallPageRenderInput<'_>) -> Response {
    let data = InstallPageData {
        username: input.username,
        email: input.email,
        domain: input.domain,
        error: input.error,
        csrf_token: input.csrf_token,
        algorithms: install_algorithms(input.selected_algorithm),
    };

    let mut response = Response::new();
    match web::tera::render_view(input.ctx, input.headers, "install/index.html", data) {
        Ok(body) => render_html(&mut response, StatusCode::OK, body),
        Err(error) => render_app_error(&mut response, input.headers, input.ctx, error),
    }
    response
}

#[handler]
async fn install_page(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    if *ctx.settings().installation_initialized().current_value() {
        redirect_to(res, "/login");
        return Ok(());
    }

    *res = render_install_page(InstallPageRenderInput {
        ctx: &ctx,
        headers: &headers,
        csrf_token: csrf_token(depot),
        username: String::new(),
        email: String::new(),
        domain: String::new(),
        selected_algorithm: "ecdsa-p256",
        error: None,
    });
    Ok(())
}

#[handler]
async fn install_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let form: InstallForm = parse_form(req).await?;
    if *ctx.settings().installation_initialized().current_value() {
        redirect_to(res, "/login");
        return Ok(());
    }

    let algorithm = match parse_algorithm(&form.key_algorithm) {
        Ok(algorithm) => algorithm,
        Err(message) => {
            *res = render_install_page(InstallPageRenderInput {
                ctx: &ctx,
                headers: &headers,
                csrf_token: csrf_token(depot),
                username: form.username,
                email: form.email,
                domain: form.domain,
                selected_algorithm: &form.key_algorithm,
                error: Some(message),
            });
            return Ok(());
        }
    };

    let input = InstallInput {
        username: form.username.clone(),
        email: form.email.clone(),
        password: form.password.clone(),
        domain: form.domain.clone(),
        key_algorithm: algorithm,
    };

    match ctx.services().install().install(input).await {
        Ok(_) => {
            ctx.lifecycle().request_shutdown();
            redirect_to(res, "/login");
        }
        Err(error) => {
            log_install_failure(&error, &form);
            *res = render_install_page(InstallPageRenderInput {
                ctx: &ctx,
                headers: &headers,
                csrf_token: csrf_token(depot),
                username: form.username,
                email: form.email,
                domain: form.domain,
                selected_algorithm: &form.key_algorithm,
                error: Some(super::response::error_message(
                    ctx.resources().i18n(),
                    &resolve_locale_from_headers(&headers),
                    &error,
                )),
            });
        }
    }
    Ok(())
}

fn install_algorithms(selected: &str) -> Vec<InstallAlgorithmOption> {
    [
        ("ecdsa-p256", "ECDSA P-256"),
        ("ecdsa-p384", "ECDSA P-384"),
        ("ecdsa-p521", "ECDSA P-521"),
        ("ecdsa-secp256k1", "ECDSA secp256k1"),
        ("ed25519", "Ed25519"),
        ("ed448", "Ed448"),
        ("rsa-2048", "RSA 2048"),
        ("rsa-3072", "RSA 3072"),
        ("rsa-4096", "RSA 4096"),
    ]
    .into_iter()
    .map(|(value, label)| InstallAlgorithmOption {
        value,
        label,
        selected: value == selected,
    })
    .collect()
}

fn parse_algorithm(value: &str) -> Result<AsymmetricKeyAlgorithm, String> {
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
        _ => Err("unsupported key algorithm".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use identity_application::error::{AppError, codes::common::CommonErrorCode};

    use super::{InstallFailureLogContext, InstallForm, should_log_install_failure_as_error};

    #[test]
    fn internal_install_errors_are_logged_with_sanitized_context() {
        let form = InstallForm {
            username: "admin".to_owned(),
            email: "admin@example.com".to_owned(),
            password: "super-secret-password".to_owned(),
            domain: "identity.example.com".to_owned(),
            key_algorithm: "ed25519".to_owned(),
        };
        let error = AppError::from_code(CommonErrorCode::InternalError);

        let context = InstallFailureLogContext::from_form(&form);

        assert!(should_log_install_failure_as_error(&error));
        assert_eq!(context.domain, "identity.example.com");
        assert_eq!(context.key_algorithm, "ed25519");
    }
}
