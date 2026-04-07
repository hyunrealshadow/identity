use std::error::Error as StdError;

use axum::extract::{FromRequest, rejection::JsonRejection};
use axum::{
    Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use unic_langid::LanguageIdentifier;

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers},
    web::views::auth::BusinessErrorResponse,
};

pub fn error_message(i18n: &I18n, locale: &LanguageIdentifier, error: &AppError) -> String {
    if let Some(message) = error
        .params()
        .get("message")
        .filter(|message| !message.is_empty())
    {
        return message.to_owned();
    }

    if error.params().is_empty() {
        i18n.t_code(locale, error.code())
    } else {
        i18n.t_code_with_params(locale, error.code(), error.params())
    }
}

pub fn error_response(i18n: &I18n, locale: &LanguageIdentifier, error: AppError) -> Response {
    let status = error.kind().http_status();

    if status.is_server_error() {
        tracing::error!(
            error = %error,
            source = ?error.source(),
            code = error.code(),
            "internal error"
        );
    } else {
        tracing::debug!(error = %error, code = error.code(), "business error");
    }

    let message = error_message(i18n, locale, &error);
    let body = BusinessErrorResponse::new(error.code(), message);
    (status, Json(body)).into_response()
}

pub fn error_response_from_headers(i18n: &I18n, headers: &HeaderMap, error: AppError) -> Response {
    let locale = resolve_locale_from_headers(headers);
    error_response(i18n, &locale, error)
}

#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct AppJson<T>(pub T);

impl<T> IntoResponse for AppJson<T>
where
    Json<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let Some(i18n) = error_i18n() {
            return error_response(i18n, i18n.fallback_locale(), self);
        }

        let status = self.kind().http_status();
        let body = BusinessErrorResponse::new(self.code(), self.code().to_string());
        (status, Json(body)).into_response()
    }
}

impl From<JsonRejection> for AppError {
    fn from(_: JsonRejection) -> Self {
        Self::from_code(CommonErrorCode::InvalidRequest)
    }
}
