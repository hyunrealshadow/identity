use std::{collections::HashMap, path::Path, sync::Arc};

use fluent_templates::{ArcLoader, Loader};
use http::HeaderMap;
use tera::{Context, Function, Tera, Value};
use unic_langid::{LanguageIdentifier, langid};

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    boot::AppState,
    infrastructure::i18n::{I18n, resolve_locale_from_headers},
};

struct LocaleAwareFluentLoader {
    loader: Arc<ArcLoader>,
    default_locale: LanguageIdentifier,
}

impl Function for LocaleAwareFluentLoader {
    fn call(&self, args: &HashMap<String, Value>) -> tera::Result<Value> {
        let key = args
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("t(): missing required argument `key`"))?;

        let locale = match args.get("lang").and_then(Value::as_str) {
            Some(lang) => lang
                .parse()
                .map_err(|e| tera::Error::msg(format!("t(): invalid `lang` value: {e}")))?,
            None => self.default_locale.clone(),
        };

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
        tera.register_function(
            "t",
            LocaleAwareFluentLoader {
                loader,
                default_locale: langid!("en-US"),
            },
        );
    }

    Ok(Arc::new(tera))
}

fn render_with_locale(
    tera: &Tera,
    loader: Option<Arc<ArcLoader>>,
    locale: LanguageIdentifier,
    template: &str,
    context: &Context,
) -> tera::Result<String> {
    let mut tera = tera.clone();

    if let Some(loader) = loader {
        tera.register_function(
            "t",
            LocaleAwareFluentLoader {
                loader,
                default_locale: locale,
            },
        );
    }

    tera.render(template, context)
}

pub fn render_view<T: serde::Serialize>(
    state: &AppState,
    headers: &HeaderMap,
    template: &str,
    data: T,
) -> Result<String, AppError> {
    match serde_json::to_value(data) {
        Err(e) => {
            tracing::error!(error = %e, "render_view: serialise failed");
            Err(AppError::from_code(CommonErrorCode::InternalError))
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
                    Err(AppError::from_code(CommonErrorCode::InternalError))
                }
                Ok(context) => match render_with_locale(
                    state.resources().tera(),
                    state.resources().i18n().loader(),
                    resolve_locale_from_headers(headers),
                    template,
                    &context,
                ) {
                    Ok(body) => Ok(body),
                    Err(e) => {
                        tracing::error!(error = %e, template, "render_view: template render failed");
                        Err(AppError::from_code(CommonErrorCode::InternalError))
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tera::Context;
    use unic_langid::langid;

    use super::{build_i18n, build_tera, render_with_locale};
    use crate::application::error::params::ErrorParams;
    use crate::web::views::install::{InstallAlgorithmOption, InstallPageData};

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

    #[test]
    fn template_uses_context_lang_when_t_lang_is_omitted() {
        let i18n = build_i18n().expect("i18n should load from assets/i18n");
        let tera = build_tera(i18n.loader()).expect("tera should build from assets/views");
        let data = InstallPageData {
            username: "admin".to_owned(),
            email: "admin@example.com".to_owned(),
            domain: "identity.example.com".to_owned(),
            error: None,
            csrf_token: "csrf-token".to_owned(),
            algorithms: vec![InstallAlgorithmOption {
                value: "ed25519",
                label: "Ed25519",
                selected: true,
            }],
        };

        let mut value = serde_json::to_value(data).expect("install data should serialize");
        value
            .as_object_mut()
            .expect("install page data should serialize to object")
            .insert("lang".to_owned(), tera::Value::String("zh-CN".to_owned()));
        let context = Context::from_value(value).expect("context should build");

        let rendered = render_with_locale(
            tera.as_ref(),
            i18n.loader(),
            langid!("zh-CN"),
            "install/index.html",
            &context,
        )
        .expect("install template should render");

        assert!(rendered.contains("使用条款"), "{rendered}");
        assert!(!rendered.contains("Unknown localization key"), "{rendered}");
    }

    #[test]
    fn install_template_renders_install_specific_copy_in_detected_locale() {
        let i18n = build_i18n().expect("i18n should load from assets/i18n");
        let tera = build_tera(i18n.loader()).expect("tera should build from assets/views");
        let data = InstallPageData {
            username: "admin".to_owned(),
            email: "admin@example.com".to_owned(),
            domain: "identity.example.com".to_owned(),
            error: None,
            csrf_token: "csrf-token".to_owned(),
            algorithms: vec![InstallAlgorithmOption {
                value: "ed25519",
                label: "Ed25519",
                selected: true,
            }],
        };

        let mut value = serde_json::to_value(data).expect("install data should serialize");
        value
            .as_object_mut()
            .expect("install page data should serialize to object")
            .insert("lang".to_owned(), tera::Value::String("zh-CN".to_owned()));
        let context = Context::from_value(value).expect("context should build");

        let rendered = render_with_locale(
            tera.as_ref(),
            i18n.loader(),
            langid!("zh-CN"),
            "install/index.html",
            &context,
        )
        .expect("install template should render");

        assert!(rendered.contains("初始化安装"), "{rendered}");
    }
}
