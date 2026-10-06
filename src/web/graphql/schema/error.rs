use std::{backtrace::Backtrace, error::Error as StdError};

use async_graphql::{Context, Error, ErrorExtensions, Value};
use identity_application::error::{AppError, ErrorDiagnostics, kind::ErrorKind};
use serde_json::{Value as SerdeJsonValue, json};
use tracing::error;

use super::authorization::request_context;
use crate::controllers::response::{error_message, log_app_error};

pub(super) fn internal_error(error: impl StdError + 'static) -> Error {
    let diagnostics = ErrorDiagnostics::from_error(&error);
    let fallback = diagnostics
        .backtrace
        .is_none()
        .then(Backtrace::force_capture);
    let backtrace = diagnostics.backtrace.or(fallback.as_ref());
    error!(
        error = %error,
        has_source = error.source().is_some(),
        error_cause = %diagnostics.cause,
        error_operation = diagnostics.operation,
        stacktrace = backtrace.map(ToString::to_string),
        "graphql resolver failed"
    );
    Error::new("internal server error")
}

pub(super) fn app_error(ctx: &Context<'_>, error: AppError) -> Error {
    let request = match request_context(ctx) {
        Ok(request) => request,
        Err(error) => return error,
    };
    log_app_error(&error, "graphql application request failed");
    let i18n = request.state.resources().i18n();
    let message = error_message(i18n, &request.locale, &error);
    let kind = match error.kind() {
        ErrorKind::NotFound => "not_found",
        ErrorKind::Unauthorized => "unauthorized",
        ErrorKind::Forbidden => "forbidden",
        ErrorKind::Conflict => "conflict",
        ErrorKind::Validation => "validation",
        ErrorKind::RateLimit => "rate_limit",
        ErrorKind::Gone => "gone",
        ErrorKind::Internal => "internal",
    };
    let fields = error
        .validation()
        .map(|validation| {
            validation
                .fields()
                .iter()
                .map(|field| {
                    let field_message = field
                        .params()
                        .get("message")
                        .filter(|message| !message.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            i18n.t_code_with_params(&request.locale, field.code(), field.params())
                        });
                    json!({
                        "field": field.field(),
                        "code": field.code(),
                        "message": field_message,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Error::new(message).extend_with(|_, extensions| {
        extensions.set("kind", kind);
        extensions.set("code", error.code());
        extensions.set(
            "fields",
            Value::from_json(SerdeJsonValue::Array(fields)).unwrap_or(Value::Null),
        );
    })
}
