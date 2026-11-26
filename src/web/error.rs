//! How an [`AppError`] is presented, shared by every web transport.
//!
//! HTTP JSON bodies, HTML error pages, OAuth/OIDC protocol errors and GraphQL
//! errors all take their status, localized message, field errors,
//! authorization challenge and log record from here, so the transports differ
//! only in envelope shape.

use std::error::Error as StdError;

use http::{HeaderMap, StatusCode};
use identity_application::error::{
    AppError, ErrorDiagnostics, StepUpChallenge, code::AppErrorCode,
    codes::common::CommonErrorCode, kind::ErrorKind, params::ErrorParams,
};
use serde_json::{Value, json};
use tracing::{Level, event};
use unic_langid::LanguageIdentifier;

use crate::infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers};

pub fn error_http_status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        ErrorKind::Validation => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorKind::RateLimit => StatusCode::TOO_MANY_REQUESTS,
        ErrorKind::Gone => StatusCode::GONE,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub fn app_error_log_level(error: &AppError) -> Level {
    match error.kind() {
        ErrorKind::Internal => Level::ERROR,
        ErrorKind::Unauthorized | ErrorKind::Forbidden | ErrorKind::RateLimit => Level::WARN,
        ErrorKind::NotFound | ErrorKind::Conflict | ErrorKind::Validation | ErrorKind::Gone => {
            Level::DEBUG
        }
    }
}

pub fn log_app_error(error: &AppError, message: &'static str) {
    let diagnostics = ErrorDiagnostics::from_error(error);
    macro_rules! log {
        ($level:expr) => {
            event!(
                $level,
                error_code = error.code(),
                error_kind = ?error.kind(),
                error = %error,
                has_source = error.source().is_some(),
                error_cause = %diagnostics.cause,
                error_operation = diagnostics.operation,
                stacktrace = diagnostics.backtrace.map(ToString::to_string),
                "{message}"
            )
        };
    }
    match app_error_log_level(error) {
        Level::ERROR => log!(Level::ERROR),
        Level::WARN => log!(Level::WARN),
        _ => log!(Level::DEBUG),
    }
}

/// Localized message for `error`.
pub fn error_message(i18n: &I18n, locale: &LanguageIdentifier, error: &AppError) -> String {
    code_message(i18n, locale, error.code(), error.params())
}

/// Run `render` with the process error catalog and the request's negotiated
/// language. Without a catalog every message is the generic fallback, so
/// callers need no separate unlocalized branch.
pub fn with_request_catalog<R>(
    headers: &HeaderMap,
    render: impl FnOnce(&I18n, &LanguageIdentifier) -> R,
) -> R {
    let locale = resolve_locale_from_headers(headers);
    match error_i18n() {
        Some(i18n) => render(i18n, &locale),
        None => render(&I18n::disabled(), &locale),
    }
}

/// Localized message for `error` in the request's negotiated language.
pub fn request_error_message(headers: &HeaderMap, error: &AppError) -> String {
    with_request_catalog(headers, |i18n, locale| error_message(i18n, locale, error))
}

/// Catalog message for `code`, or the generic internal message when the
/// catalog lacks it, so raw `E<code>` keys never reach clients.
pub fn code_message(
    i18n: &I18n,
    locale: &LanguageIdentifier,
    code: u32,
    params: &ErrorParams,
) -> String {
    render(i18n, locale, code, params).unwrap_or_else(|| {
        render(
            i18n,
            locale,
            CommonErrorCode::InternalError.code(),
            &ErrorParams::new(),
        )
        .unwrap_or_else(|| static_generic_message(locale))
    })
}

fn render(
    i18n: &I18n,
    locale: &LanguageIdentifier,
    code: u32,
    params: &ErrorParams,
) -> Option<String> {
    let rendered = if params.is_empty() {
        i18n.t_code(locale, code)
    } else {
        i18n.t_code_with_params(locale, code, params)
    };
    (rendered != format!("E{code}")).then_some(rendered)
}

fn static_generic_message(locale: &LanguageIdentifier) -> String {
    if locale.language.as_str() == "zh" {
        "发生意外错误，请重试".to_owned()
    } else {
        "An unexpected error occurred. Please try again.".to_owned()
    }
}

/// A localized field-level validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedFieldError {
    pub field: String,
    pub code: u32,
    pub message: String,
}

pub fn field_errors(
    i18n: &I18n,
    locale: &LanguageIdentifier,
    error: &AppError,
) -> Vec<LocalizedFieldError> {
    error
        .validation()
        .map(|validation| {
            validation
                .fields()
                .iter()
                .map(|field| LocalizedFieldError {
                    field: client_field_path(field.field()),
                    code: field.code(),
                    message: code_message(i18n, locale, field.code(), field.params()),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Application field paths are snake_case (`names.0.locale`); clients see the
/// lowerCamelCase spelling of their inputs (`expectedVersion`).
fn client_field_path(path: &str) -> String {
    path.split('.')
        .map(|segment| {
            let mut out = String::with_capacity(segment.len());
            let mut upper = false;
            for ch in segment.chars() {
                if ch == '_' && !out.is_empty() {
                    upper = true;
                } else if upper {
                    out.extend(ch.to_uppercase());
                    upper = false;
                } else {
                    out.push(ch);
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The authorization challenge a client can satisfy, named after the bearer
/// token error codes of RFC 9470 and RFC 6750.
pub fn challenge(error: &AppError) -> Option<Value> {
    if let Some(step_up) = error.step_up() {
        let mut challenge = json!({ "error": "insufficient_user_authentication" });
        if let Some(acr) = step_up.acr {
            challenge["acrValues"] = json!(acr.as_str());
        }
        if let Some(max_age) = step_up.max_age_secs {
            challenge["maxAge"] = json!(max_age);
        }
        return Some(challenge);
    }
    let scopes = error.required_scopes();
    (!scopes.is_empty()).then(|| json!({ "error": "insufficient_scope", "scopes": scopes }))
}

/// RFC 9470 `WWW-Authenticate` value asking for stronger or fresher
/// authentication.
pub fn step_up_www_authenticate(realm: &str, challenge: &StepUpChallenge) -> String {
    let mut parameters = vec![
        format!("Bearer realm=\"{realm}\""),
        "error=\"insufficient_user_authentication\"".to_owned(),
        "error_description=\"A different authentication level or more recent authentication is required\"".to_owned(),
    ];
    if let Some(acr) = challenge.acr {
        parameters.push(format!("acr_values=\"{}\"", acr.as_str()));
    }
    if let Some(max_age) = challenge.max_age_secs {
        parameters.push(format!("max_age=\"{max_age}\""));
    }
    parameters.join(", ")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Error, Result as IoResult, Write},
        sync::{Arc, Mutex},
    };

    use identity_application::error::{
        ErrorContext,
        codes::{common, install},
    };
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt;
    use unic_langid::langid;

    use super::*;

    #[test]
    fn logs_distinguish_internal_failures_rejections_and_validation() {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> IoResult<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        with_default(subscriber, || {
            let error = common::error::InternalError.with_source(ErrorContext::new(
                "client_authorization.lock_refresh_family",
                Error::other("database unavailable"),
            ));
            log_app_error(&error, "internal-test");
            log_app_error(&common::error::Unauthorized.into(), "rejection-test");
            log_app_error(&common::error::InvalidRequest.into(), "validation-test");
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let internal = output
            .lines()
            .find(|line| line.contains("internal-test"))
            .unwrap();
        assert!(internal.contains("ERROR") && internal.contains("has_source=true"));
        assert!(internal.contains("database unavailable"));
        assert_eq!(internal.matches("database unavailable").count(), 1);
        assert!(internal.contains("error_operation=\"client_authorization.lock_refresh_family\""));
        assert!(internal.contains("stacktrace="));
        assert!(!internal.contains("error_file=") && !internal.contains("app_error_line="));
        // Backtrace frames may print function types such as `fn() -> T`, so
        // only the structured fields before the stack trace are checked for a
        // flattened source chain.
        let (fields, _) = internal.split_once("stacktrace=").unwrap();
        assert!(!fields.contains("source_chain") && !fields.contains(" -> "));
        let rejection = output
            .lines()
            .find(|line| line.contains("rejection-test"))
            .unwrap();
        assert!(rejection.contains("WARN") && rejection.contains("has_source=false"));
        let validation = output
            .lines()
            .find(|line| line.contains("validation-test"))
            .unwrap();
        assert!(validation.contains("DEBUG"));
    }

    #[test]
    fn a_missing_catalog_entry_falls_back_to_the_generic_message() {
        let error = install::error::EmailInvalid
            .into_error()
            .with_field_error("email", install::error::EmailInvalid);

        assert_eq!(
            error_message(&I18n::disabled(), &langid!("zh-CN"), &error),
            "发生意外错误，请重试"
        );
        assert_eq!(
            field_errors(&I18n::disabled(), &langid!("en-US"), &error)[0].message,
            "An unexpected error occurred. Please try again."
        );
    }

    #[test]
    fn field_paths_use_the_client_input_spelling() {
        assert_eq!(client_field_path("expected_version"), "expectedVersion");
        assert_eq!(client_field_path("names.0.locale"), "names.0.locale");
        assert_eq!(
            client_field_path("platforms.redirect_uris"),
            "platforms.redirectUris"
        );
        assert_eq!(client_field_path("roleIds"), "roleIds");
    }

    #[test]
    fn errors_without_authorization_details_have_no_challenge() {
        assert!(challenge(&common::error::Forbidden.into_error()).is_none());
    }
}
