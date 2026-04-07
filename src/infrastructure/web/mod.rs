use std::{collections::HashMap, path::Path, sync::Arc};

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use fluent_templates::{ArcLoader, Loader};
use tera::{Context, Function, Tera, Value};
use unic_langid::langid;

use crate::{
    boot::AppState,
    infrastructure::i18n::{I18n, resolve_locale_from_headers},
};

struct LocaleAwareFluentLoader {
    loader: Arc<ArcLoader>,
}

impl Function for LocaleAwareFluentLoader {
    fn call(&self, args: &HashMap<String, Value>) -> tera::Result<Value> {
        let key = args
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("t(): missing required argument `key`"))?;

        let locale = args
            .get("lang")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("t(): missing required argument `lang`"))?
            .parse()
            .map_err(|e| tera::Error::msg(format!("t(): invalid `lang` value: {e}")))?;

        Ok(Value::String(self.loader.lookup(&locale, key).to_string()))
    }
}

pub fn build_i18n() -> Result<I18n, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let path = Path::new("assets/i18n");
    if !path.exists() {
        return Ok(I18n::disabled());
    }

    let loader = ArcLoader::builder(path, langid!("en-US"))
        .customize(|bundle| bundle.set_use_isolating(false))
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(I18n::enabled(Arc::new(loader)))
}

pub fn build_tera(
    loader: Option<Arc<ArcLoader>>,
) -> Result<Arc<Tera>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut tera = Tera::new("assets/views/**/*")?;

    if let Some(loader) = loader {
        tera.register_function("t", LocaleAwareFluentLoader { loader });
    }

    Ok(Arc::new(tera))
}

pub fn render_view<T: serde::Serialize>(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    template: &str,
    data: T,
) -> Response {
    match serde_json::to_value(data) {
        Err(e) => {
            tracing::error!(error = %e, "render_view: serialise failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(mut data) => {
            let locale = resolve_locale_from_headers(headers).to_string();
            if let Some(object) = data.as_object_mut() {
                object
                    .entry("lang")
                    .or_insert_with(|| Value::String(locale));
            }

            match Context::from_value(data) {
                Err(e) => {
                    tracing::error!(error = %e, "render_view: context build failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
                Ok(context) => match state.resources().tera().render(template, &context) {
                    Ok(body) => Html(body).into_response(),
                    Err(e) => {
                        tracing::error!(error = %e, template, "render_view: template render failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use unic_langid::langid;

    use super::build_i18n;
    use crate::application::error::params::ErrorParams;

    #[test]
    fn build_i18n_loads_split_error_files_with_args() {
        let i18n = build_i18n().expect("i18n should load from assets/i18n");
        let params = ErrorParams::new()
            .insert("identifier", "alice@example.com")
            .insert("identifier_kind", "email");

        let translated = i18n.t_code_with_params(&langid!("en-US"), 2000, &params);

        assert_eq!(
            translated,
            "The account does not exist. Enter a different email or username."
        );
    }
}
