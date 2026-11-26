//! Loading the Fluent catalogs and the functions their messages use.

use std::{error::Error as StdError, io::Error as IoError, sync::Arc};

use fluent_templates::{
    ArcLoader, FluentBundle,
    fluent_bundle::{FluentArgs, FluentValue},
};
use icu_list::{
    ListFormatter,
    options::{ListFormatterOptions, ListLength},
};
use icu_locale_core::LanguageIdentifier as IcuLocaleCoreLanguageIdentifier;
use icu_provider::DataError;
use tracing::warn;
use unic_langid::langid;
use writeable::Writeable;

use super::{I18n, catalog};
use crate::assets::workspace_path;

pub fn build_i18n() -> Result<I18n, Box<dyn StdError + Send + Sync + 'static>> {
    let path = workspace_path("assets/i18n");
    if !path.exists() {
        return Ok(I18n::disabled());
    }

    catalog::validate_error_catalogs(&path).map_err(IoError::other)?;

    let loader = ArcLoader::builder(path.as_path(), langid!("en-US"))
        .customize(|bundle| {
            bundle.set_use_isolating(false);
            register_list_function(bundle);
        })
        .build()
        .map_err(|e| IoError::other(e.to_string()))?;

    Ok(I18n::enabled(Arc::new(loader)))
}

/// Register a `LIST()` Fluent function that joins a comma-separated string of
/// items using ICU's locale-aware list formatting.
///
/// Usage in FTL:
///   `{ LIST($fields) }`                  - conjunction (default), e.g. "A and B"
///   `{ LIST($fields, listType: "or") }`  - disjunction, e.g. "A or B"
///   `{ LIST($fields, listType: "unit") }` - unit list, e.g. "A B"
pub(crate) fn register_list_function<R>(bundle: &mut FluentBundle<R>) {
    let langid = bundle.locales.first().cloned().unwrap_or(langid!("en-US"));
    let locale: IcuLocaleCoreLanguageIdentifier = langid
        .to_string()
        .parse()
        .unwrap_or_else(|_| "en-US".parse().unwrap());
    let opts = ListFormatterOptions::default().with_length(ListLength::Narrow);
    let prefs = locale.into();

    struct ListFormatters {
        and: ListFormatter,
        or: ListFormatter,
        unit: ListFormatter,
    }

    let Ok(formatters) = (|| -> Result<ListFormatters, DataError> {
        Ok(ListFormatters {
            and: ListFormatter::try_new_and(prefs, opts)?,
            or: ListFormatter::try_new_or(prefs, opts)?,
            unit: ListFormatter::try_new_unit(prefs, opts)?,
        })
    })() else {
        warn!("icu ListFormatter init failed; LIST() will pass through");
        return;
    };

    let formatters: &'static ListFormatters = Box::leak(Box::new(formatters));

    bundle
        .add_function(
            "LIST",
            move |positional: &[FluentValue], named: &FluentArgs| {
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
            },
        )
        .expect("registering LIST() Fluent function");
}
