use std::{backtrace::Backtrace, error::Error as StdError};

use async_graphql::{Context, Error, ErrorExtensionValues, ErrorExtensions, Value};
use identity_application::{
    authorization::DEFAULT_RECENT_AAL2_TTL,
    error::{
        AppError, ErrorDiagnostics,
        code::AppErrorCode,
        codes::{authorization::AuthorizationErrorCode, graphql::GraphqlErrorCode},
        kind::ErrorKind,
        params::ErrorParams,
    },
};
use serde_json::{Value as SerdeJsonValue, json};
use tracing::error;
use unic_langid::{LanguageIdentifier, langid};

use super::{authorization::request_context, context::RequestContext};
use crate::{
    controllers::response::{error_message, log_app_error},
    infrastructure::i18n::{I18n, error_i18n},
};

/// Request/trace correlation copied from [`crate::middleware::RequestCorrelation`].
pub(super) struct Correlation {
    request_id: String,
    trace_id: Option<String>,
}

impl Correlation {
    pub(super) fn apply(&self, extensions: &mut ErrorExtensionValues) {
        if !self.request_id.is_empty() {
            extensions.set("requestId", self.request_id.clone());
        }
        if let Some(trace_id) = &self.trace_id {
            extensions.set("traceId", trace_id.clone());
        }
    }
}

pub(super) fn correlation(ctx: &Context<'_>) -> Correlation {
    match ctx.data::<RequestContext>() {
        Ok(request) => Correlation {
            request_id: request.correlation.request_id.clone(),
            trace_id: request.correlation.trace_id.clone(),
        },
        Err(_) => Correlation {
            request_id: String::new(),
            trace_id: None,
        },
    }
}

fn context_i18n(ctx: &Context<'_>) -> (I18n, LanguageIdentifier) {
    match ctx.data::<RequestContext>() {
        Ok(request) => (
            request.state.resources().i18n().clone(),
            request.locale.clone(),
        ),
        Err(_) => (
            error_i18n().cloned().unwrap_or_else(I18n::disabled),
            langid!("en-US"),
        ),
    }
}

fn generic_message(i18n: &I18n, locale: &LanguageIdentifier) -> String {
    let code = GraphqlErrorCode::Internal;
    let key = format!("E{}", code.code());
    let rendered = i18n.t_code(locale, code.code());
    if rendered == key {
        static_generic_message(locale)
    } else {
        rendered
    }
}

fn static_generic_message(locale: &LanguageIdentifier) -> String {
    if locale.language.as_str() == "zh" {
        "发生意外错误，请重试。".to_owned()
    } else {
        "An unexpected error occurred. Please try again.".to_owned()
    }
}

/// Render a catalog message, substituting the localized generic internal
/// message when the catalog is missing the requested key. This is the response
/// safety net that keeps raw `E<code>` keys and Fluent source text away from
/// clients.
pub(super) fn localized_message(
    ctx: &Context<'_>,
    code: GraphqlErrorCode,
    params: &ErrorParams,
) -> String {
    let (i18n, locale) = context_i18n(ctx);
    catalog_message(&i18n, &locale, code, params)
}

fn catalog_message(
    i18n: &I18n,
    locale: &LanguageIdentifier,
    code: GraphqlErrorCode,
    params: &ErrorParams,
) -> String {
    let key = format!("E{}", code.code());
    let rendered = if params.is_empty() {
        i18n.t_code(locale, code.code())
    } else {
        i18n.t_code_with_params(locale, code.code(), params)
    };
    if rendered == key {
        generic_message(i18n, locale)
    } else {
        rendered
    }
}

fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::NotFound => "not_found",
        ErrorKind::Unauthorized => "unauthorized",
        ErrorKind::Forbidden => "forbidden",
        ErrorKind::Conflict => "conflict",
        ErrorKind::Validation => "validation",
        ErrorKind::RateLimit => "rate_limit",
        ErrorKind::Gone => "gone",
        ErrorKind::Internal => "internal",
    }
}

/// Build a localized GraphQL error from a stable code and safe parameters.
/// The extension `code` is the numeric application code.
pub(super) fn coded_error(ctx: &Context<'_>, code: GraphqlErrorCode, params: ErrorParams) -> Error {
    let message = localized_message(ctx, code, &params);
    let kind = kind_name(code.kind());
    let correlation = correlation(ctx);
    Error::new(message).extend_with(|_, extensions| {
        extensions.set("kind", kind);
        extensions.set("code", code.code());
        correlation.apply(extensions);
    })
}

fn log_internal(error: &(impl StdError + 'static), operation: &'static str) {
    let diagnostics = ErrorDiagnostics::from_error(error);
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
        "{operation}"
    );
}

/// Internal adapter failure: localized generic message to the client, full
/// diagnostic context to the server log only.
pub(super) fn internal_error(ctx: &Context<'_>, error: impl StdError + 'static) -> Error {
    log_internal(&error, "graphql resolver failed");
    let (i18n, locale) = context_i18n(ctx);
    let message = generic_message(&i18n, &locale);
    let correlation = correlation(ctx);
    Error::new(message).extend_with(|_, extensions| {
        extensions.set("kind", "internal");
        extensions.set("code", GraphqlErrorCode::Internal.code());
        correlation.apply(extensions);
    })
}

pub(super) fn app_error(ctx: &Context<'_>, error: AppError) -> Error {
    let request = match request_context(ctx) {
        Ok(request) => request,
        Err(error) => return error,
    };
    log_app_error(&error, "graphql application request failed");
    let i18n = request.state.resources().i18n();
    let mut message = error_message(i18n, &request.locale, &error);
    let key = format!("E{}", error.code());
    if message == key {
        message = generic_message(i18n, &request.locale);
    }
    let kind = kind_name(error.kind());
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
                            let rendered = i18n.t_code_with_params(
                                &request.locale,
                                field.code(),
                                field.params(),
                            );
                            if rendered == format!("E{}", field.code()) {
                                generic_message(i18n, &request.locale)
                            } else {
                                rendered
                            }
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
    let correlation = Correlation {
        request_id: request.correlation.request_id.clone(),
        trace_id: request.correlation.trace_id.clone(),
    };
    Error::new(message).extend_with(|_, extensions| {
        extensions.set("kind", kind);
        extensions.set("code", error.code());
        if error.code() == AuthorizationErrorCode::MissingHumanAuthentication.code() {
            extensions.set("applicationCode", error.code());
            extensions.set("code", "insufficient_user_authentication");
            extensions.set("acr_values", "aal2");
            if error.params().get("required_authentication") == Some("recent_aal2") {
                extensions.set("max_age", DEFAULT_RECENT_AAL2_TTL.as_secs());
            }
        }
        extensions.set(
            "fields",
            Value::from_json(SerdeJsonValue::Array(fields)).unwrap_or(Value::Null),
        );
        correlation.apply(extensions);
    })
}
