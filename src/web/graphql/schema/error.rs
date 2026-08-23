use std::error::Error as _;

use async_graphql::{Context, Error, ErrorExtensions};
use identity_application::error::{AppError, kind::ErrorKind};

use super::authorization::request_context;

pub(super) fn internal_error(error: impl std::fmt::Display) -> Error {
    tracing::error!(error = %error, "graphql resolver failed");
    Error::new("internal server error")
}

pub(super) fn app_error(ctx: &Context<'_>, error: AppError) -> Error {
    let request = match request_context(ctx) {
        Ok(request) => request,
        Err(error) => return error,
    };
    if error.kind() == ErrorKind::Internal {
        tracing::error!(
            error = %error,
            source = ?error.source(),
            code = error.code(),
            request_id = request.request_id,
            "graphql application error"
        );
    }
    let i18n = request.state.resources().i18n();
    let message = crate::controllers::response::error_message(i18n, &request.locale, &error);
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
                    serde_json::json!({
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
        extensions.set("requestId", request.request_id.as_str());
        extensions.set(
            "fields",
            async_graphql::Value::from_json(serde_json::Value::Array(fields))
                .unwrap_or(async_graphql::Value::Null),
        );
    })
}
