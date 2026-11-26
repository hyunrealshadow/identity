//! The single projection from [`AppError`] to a GraphQL error.
//!
//! Resolvers, guards, input adapters and schema extensions all build an
//! `AppError` and render it here, so every GraphQL error carries the same
//! localized message, `kind`, numeric `code`, field errors and authorization
//! challenge. Request correlation is attached afterwards by the transport.

use std::{error::Error as StdError, sync::Arc};

use async_graphql::{Context, Error, ErrorExtensionValues, Value};
use identity_application::error::{
    AppError, code::AppErrorCode, codes::graphql::GraphqlErrorCode, params::ErrorParams,
};
use serde_json::{Value as SerdeJsonValue, json};
use unic_langid::{LanguageIdentifier, langid};

use super::context::RequestContext;
use crate::{
    controllers::response::log_app_error,
    infrastructure::i18n::{I18n, error_i18n},
};

/// Log and render an application error raised while resolving a GraphQL field.
pub(super) fn app_error(ctx: &Context<'_>, error: impl Into<AppError>) -> Error {
    let error = error.into();
    log_app_error(&error, "graphql request failed");
    match ctx.data::<RequestContext>() {
        Ok(request) => project(request.state.resources().i18n(), &request.locale, &error),
        Err(_) => {
            let i18n = error_i18n().cloned().unwrap_or_else(I18n::disabled);
            project(&i18n, &langid!("en-US"), &error)
        }
    }
}

/// Internal adapter failure: the generic internal message to the client, full
/// diagnostic context to the server log only.
pub(super) fn internal_error(
    ctx: &Context<'_>,
    error: impl StdError + Send + Sync + 'static,
) -> Error {
    app_error(
        ctx,
        identity_application::error::codes::graphql::error::Internal.with_source(error),
    )
}

/// Render `error` for `locale`. The error is also kept as the GraphQL error
/// source so the transport can derive protocol headers from typed details.
pub(crate) fn project(i18n: &I18n, locale: &LanguageIdentifier, error: &AppError) -> Error {
    let text = message(i18n, locale, error.code(), error.params());
    let fields = error
        .validation()
        .map(|validation| {
            validation
                .fields()
                .iter()
                .map(|field| {
                    json!({
                        "field": field.field(),
                        "code": field.code(),
                        "message": message(i18n, locale, field.code(), field.params()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut extensions = ErrorExtensionValues::default();
    apply_extensions(&mut extensions, error, fields);
    Error {
        message: text,
        source: error.step_up().map(|challenge| Arc::new(challenge) as _),
        extensions: Some(extensions),
    }
}

fn apply_extensions(
    extensions: &mut ErrorExtensionValues,
    error: &AppError,
    fields: Vec<SerdeJsonValue>,
) {
    extensions.set("kind", error.kind().as_str());
    extensions.set("code", error.code());
    if let Some(challenge) = challenge(error) {
        extensions.set(
            "challenge",
            Value::from_json(challenge).unwrap_or(Value::Null),
        );
    }
    extensions.set(
        "fields",
        Value::from_json(SerdeJsonValue::Array(fields)).unwrap_or(Value::Null),
    );
}

/// The authorization challenge a client can satisfy, named after the bearer
/// token error codes of RFC 9470 and RFC 6750. `code` stays the catalog code.
fn challenge(error: &AppError) -> Option<SerdeJsonValue> {
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

/// Catalog message for `code`, or the generic internal message when the
/// catalog lacks it, so raw `E<code>` keys never reach clients.
fn message(i18n: &I18n, locale: &LanguageIdentifier, code: u32, params: &ErrorParams) -> String {
    render(i18n, locale, code, params).unwrap_or_else(|| {
        render(
            i18n,
            locale,
            GraphqlErrorCode::Internal.code(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use identity_application::error::{
        StepUpChallenge,
        codes::{common, graphql},
    };
    use identity_domain::auth::AuthenticationContextClass;

    fn challenge_of(projected: &Error) -> SerdeJsonValue {
        projected
            .extensions
            .as_ref()
            .unwrap()
            .get("challenge")
            .unwrap()
            .clone()
            .into_json()
            .unwrap()
    }

    #[test]
    fn step_up_keeps_the_catalog_code_and_carries_a_typed_challenge() {
        let challenge = StepUpChallenge {
            acr: Some(AuthenticationContextClass::MultiFactor),
            max_age_secs: Some(900),
        };
        let error = common::error::Unauthorized
            .into_error()
            .with_step_up(challenge);

        let projected = project(&I18n::disabled(), &langid!("en-US"), &error);
        let extensions = projected.extensions.as_ref().unwrap();

        assert_eq!(extensions.get("code"), Some(&Value::from(error.code())));
        assert_eq!(
            challenge_of(&projected),
            json!({ "error": "insufficient_user_authentication", "acrValues": "aal2", "maxAge": 900 })
        );
        let source = projected.source.as_ref().unwrap();
        assert_eq!(source.downcast_ref::<StepUpChallenge>(), Some(&challenge));
    }

    #[test]
    fn missing_scope_is_a_forbidden_rejection_with_the_scopes_to_request() {
        let error = graphql::error::InsufficientScope::new("user.read")
            .into_error()
            .with_required_scopes(["user.read"]);

        let projected = project(&I18n::disabled(), &langid!("zh-CN"), &error);
        let extensions = projected.extensions.as_ref().unwrap();

        assert_eq!(projected.message, "发生意外错误，请重试");
        assert_eq!(extensions.get("kind"), Some(&Value::from("forbidden")));
        assert_eq!(extensions.get("code"), Some(&Value::from(error.code())));
        assert_eq!(
            challenge_of(&projected),
            json!({ "error": "insufficient_scope", "scopes": ["user.read"] })
        );
        assert!(projected.source.is_none());
    }
}
