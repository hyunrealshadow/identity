use std::{collections::HashMap, path::PathBuf, sync::Arc};

use fluent_templates::{ArcLoader, Loader};
use http::HeaderMap;
use tera::{Context, Function, Tera, Value};
use unic_langid::{LanguageIdentifier, langid};

use crate::state::AppState;
use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
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
    let path = workspace_path("assets/i18n");
    if !path.exists() {
        return Ok(I18n::disabled());
    }

    let loader = ArcLoader::builder(path.as_path(), langid!("en-US"))
        .customize(|bundle| {
            bundle.set_use_isolating(false);
            register_list_function(bundle);
        })
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(I18n::enabled(Arc::new(loader)))
}

/// Register a `LIST()` Fluent function that joins a comma-separated string of
/// items using ICU's locale-aware list formatting.
///
/// Usage in FTL:
///   `{ LIST($fields) }`                  - conjunction (default), e.g. "A and B"
///   `{ LIST($fields, listType: "or") }`  - disjunction, e.g. "A or B"
///   `{ LIST($fields, listType: "unit") }` - unit list, e.g. "A B"
fn register_list_function<R>(bundle: &mut fluent_templates::FluentBundle<R>) {
    use icu_list::{
        ListFormatter,
        options::{ListFormatterOptions, ListLength},
    };
    use writeable::Writeable;
    use fluent_templates::fluent_bundle::{FluentArgs, FluentValue};

    let langid = bundle.locales.first().cloned().unwrap_or(langid!("en-US"));
    let locale: icu_locale_core::LanguageIdentifier =
        langid.to_string().parse().unwrap_or_else(|_| "en-US".parse().unwrap());
    let opts = ListFormatterOptions::default().with_length(ListLength::Narrow);
    let prefs = locale.into();

    struct ListFormatters {
        and: ListFormatter,
        or: ListFormatter,
        unit: ListFormatter,
    }

    let Ok(formatters) = (|| -> Result<ListFormatters, icu_provider::DataError> {
        Ok(ListFormatters {
            and: ListFormatter::try_new_and(prefs, opts)?,
            or: ListFormatter::try_new_or(prefs, opts)?,
            unit: ListFormatter::try_new_unit(prefs, opts)?,
        })
    })() else {
        tracing::warn!("icu ListFormatter init failed; LIST() will pass through");
        return;
    };

    let formatters: &'static ListFormatters = Box::leak(Box::new(formatters));

    bundle
        .add_function("LIST", move |positional: &[FluentValue], named: &FluentArgs| {
            let Some(FluentValue::String(raw)) = positional.first() else {
                return FluentValue::Error;
            };

            let formatter = match named.get("listType") {
                Some(FluentValue::String(s)) if s == "or" => &formatters.or,
                Some(FluentValue::String(s)) if s == "unit" => &formatters.unit,
                _ => &formatters.and,
            };

            let items: Vec<&str> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            let formatted = formatter.format(items.into_iter());
            let joined = formatted.write_to_string().into_owned();
            FluentValue::String(joined.into())
        })
        .expect("registering LIST() Fluent function");
}

pub fn build_tera(
    loader: Option<Arc<ArcLoader>>,
) -> Result<Arc<Tera>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let template_glob = workspace_path("assets/views/**/*");
    let mut tera = Tera::new(template_glob.to_string_lossy().as_ref())?;

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

fn workspace_path(relative: &str) -> PathBuf {
    let compile_time_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    let path_to_check = relative
        .find('*')
        .map(|index| PathBuf::from(&relative[..index]))
        .and_then(|path| path.parent().map(PathBuf::from))
        .map(|path| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(path)
        })
        .unwrap_or_else(|| compile_time_path.clone());

    if path_to_check.exists() {
        return compile_time_path;
    }

    PathBuf::from(relative)
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
    use identity_application::error::params::ErrorParams;

    #[derive(serde::Serialize)]
    struct InstallPageData {
        username: String,
        email: String,
        domain: String,
        error: Option<String>,
        csrf_token: String,
        algorithms: Vec<InstallAlgorithmOption>,
    }

    #[derive(serde::Serialize)]
    struct InstallAlgorithmOption {
        value: &'static str,
        label: &'static str,
        selected: bool,
    }

    #[test]
    fn build_i18n_loads_split_error_files_with_args() {
        let i18n = build_i18n().expect("i18n should load from assets/i18n");
        let params = ErrorParams::new()
            .insert("identifier", "alice@example.com")
            .insert("identifier_kind", "email");

        let translated = i18n.t_code_with_params(&langid!("en-US"), 11000, &params);

        assert_eq!(
            translated,
            "The account does not exist. Enter a different email or username."
        );
    }

    #[test]
    fn registration_errors_include_unsupported_values() {
        let i18n = build_i18n().expect("i18n should load from assets/i18n");
        let application_type_params =
            ErrorParams::new().insert("application_type", "browser_extension");
        let subject_type_params = ErrorParams::new().insert("subject_type", "sector");

        assert_eq!(
            i18n.t_code_with_params(&langid!("zh-CN"), 25002, &application_type_params),
            "不支持 application_type：browser_extension。"
        );
        assert_eq!(
            i18n.t_code_with_params(&langid!("en-US"), 25003, &subject_type_params),
            "Unsupported subject_type: sector."
        );
    }

    #[test]
    fn unsupported_error_messages_include_input_values() {
        let i18n = build_i18n().expect("i18n should load from assets/i18n");

        assert_eq!(
            i18n.t_code_with_params(
                &langid!("zh-CN"),
                24000,
                &ErrorParams::new().insert("grant_type", "device_code")
            ),
            "不支持 grant_type：device_code。"
        );
        assert_eq!(
            i18n.t_code_with_params(
                &langid!("en-US"),
                23011,
                &ErrorParams::new().insert("code_challenge_method", "S512")
            ),
            "Unsupported code_challenge_method: S512."
        );
        assert_eq!(
            i18n.t_code_with_params(
                &langid!("zh-CN"),
                22001,
                &ErrorParams::new().insert("method", "PUT")
            ),
            "不支持请求方法：PUT，请使用 GET 或 POST。"
        );
        assert_eq!(
            i18n.t_code_with_params(
                &langid!("en-US"),
                12002,
                &ErrorParams::new().insert("algorithm", "rsa(1024)")
            ),
            "Unsupported key algorithm: rsa(1024)."
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
