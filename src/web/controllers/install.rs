use axum::{
    Router,
    extract::{Form, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;

use super::shared::{append_set_cookie, ensure_csrf_token, is_secure_cookie, validate_csrf};
use crate::{
    application::{
        error::codes::common::CommonErrorCode, install::InstallInput,
        setting::runtime::SettingProvider,
    },
    boot::AppState,
    domain::key::model::AsymmetricKeyAlgorithm,
    infrastructure::{i18n::resolve_locale_from_headers, web},
    web::views::install::{InstallAlgorithmOption, InstallPageData},
};

pub fn routes() -> Router<AppState> {
    Router::new().route("/install", get(install_page).post(install_submit))
}

#[derive(Debug, Deserialize)]
struct InstallForm {
    username: String,
    email: String,
    password: String,
    domain: String,
    key_algorithm: String,
    csrf_token: String,
}

fn render_install_page(
    ctx: &AppState,
    headers: &HeaderMap,
    username: String,
    email: String,
    domain: String,
    selected_algorithm: &str,
    error: Option<String>,
) -> Response {
    let (csrf_token, csrf_cookie) = ensure_csrf_token(headers, is_secure_cookie(ctx));
    let data = InstallPageData {
        username,
        email,
        domain,
        error,
        csrf_token,
        algorithms: install_algorithms(selected_algorithm),
    };

    let mut response = web::render_view(ctx, headers, "install/index.html", data);
    if let Some(cookie) = csrf_cookie {
        append_set_cookie(&mut response, &cookie);
    }
    response
}

#[axum::debug_handler]
async fn install_page(State(ctx): State<AppState>, headers: HeaderMap) -> Response {
    if ctx.settings().installation().current_value().initialized {
        return Redirect::to("/login").into_response();
    }

    render_install_page(
        &ctx,
        &headers,
        String::new(),
        String::new(),
        String::new(),
        "ecdsa-p256",
        None,
    )
}

#[axum::debug_handler]
async fn install_submit(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<InstallForm>,
) -> Response {
    if ctx.settings().installation().current_value().initialized {
        return Redirect::to("/login").into_response();
    }

    if validate_csrf(&headers, Some(&form.csrf_token)).is_err() {
        return render_install_page(
            &ctx,
            &headers,
            form.username,
            form.email,
            form.domain,
            &form.key_algorithm,
            Some(localized_invalid_request(&ctx, &headers)),
        );
    }

    let algorithm = match parse_algorithm(&form.key_algorithm) {
        Ok(algorithm) => algorithm,
        Err(message) => {
            return render_install_page(
                &ctx,
                &headers,
                form.username,
                form.email,
                form.domain,
                &form.key_algorithm,
                Some(message),
            );
        }
    };

    let input = InstallInput {
        username: form.username.clone(),
        email: form.email.clone(),
        password: form.password,
        domain: form.domain.clone(),
        key_algorithm: algorithm,
    };

    match ctx.services().install().install(input).await {
        Ok(_) => {
            ctx.lifecycle().request_shutdown();
            Redirect::to("/login").into_response()
        }
        Err(error) => render_install_page(
            &ctx,
            &headers,
            form.username,
            form.email,
            form.domain,
            &form.key_algorithm,
            Some(super::response::error_message(
                ctx.resources().i18n(),
                &resolve_locale_from_headers(&headers),
                &error,
            )),
        ),
    }
}

fn localized_invalid_request(ctx: &AppState, headers: &HeaderMap) -> String {
    super::response::error_message(
        ctx.resources().i18n(),
        &resolve_locale_from_headers(headers),
        &crate::application::error::AppError::from_code(CommonErrorCode::InvalidRequest),
    )
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
