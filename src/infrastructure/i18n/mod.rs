use std::{
    borrow::Cow,
    collections::HashMap,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use fluent_templates::{ArcLoader, Loader, fluent_bundle::FluentValue};
use http::{HeaderMap, header::ACCEPT_LANGUAGE};
use unic_langid::{LanguageIdentifier, langid};

use identity_application::error::params::ErrorParams;

// Global I18n instance used by `AppError` response rendering to translate error
// codes without access to `AppState`. Initialised once during startup.
static ERROR_I18N: OnceLock<I18n> = OnceLock::new();

pub fn init_error_i18n(i18n: I18n) {
    let _ = ERROR_I18N.set(i18n);
}

#[must_use]
pub fn error_i18n() -> Option<&'static I18n> {
    ERROR_I18N.get()
}

pub fn resolve_locale_from_headers(headers: &HeaderMap) -> LanguageIdentifier {
    let fallback = langid!("en-US");

    let Some(raw) = headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()) else {
        return fallback;
    };

    for part in raw.split(',') {
        let locale = part.split(';').next().unwrap_or_default().trim();
        if locale.is_empty() {
            continue;
        }

        if let Ok(langid) = LanguageIdentifier::from_str(locale) {
            return langid;
        }

        if let Some(primary) = locale.split('-').next()
            && let Ok(langid) = LanguageIdentifier::from_str(primary)
        {
            return langid;
        }
    }

    fallback
}

#[derive(Clone)]
pub struct I18n {
    loader: Option<Arc<ArcLoader>>,
    fallback: LanguageIdentifier,
}

impl I18n {
    #[must_use]
    pub fn enabled(loader: Arc<ArcLoader>) -> Self {
        Self {
            loader: Some(loader),
            fallback: langid!("en-US"),
        }
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            loader: None,
            fallback: langid!("en-US"),
        }
    }

    #[must_use]
    pub fn t(&self, locale: &LanguageIdentifier, key: &str) -> String {
        self._t(locale, key)
    }

    #[must_use]
    pub fn t_code(&self, locale: &LanguageIdentifier, code: u32) -> String {
        self._t(locale, &code_key(code))
    }

    #[must_use]
    pub fn t_with_params(
        &self,
        locale: &LanguageIdentifier,
        key: &str,
        params: &ErrorParams,
    ) -> String {
        self._t_with_params(locale, key, params)
    }

    #[must_use]
    pub fn t_code_with_params(
        &self,
        locale: &LanguageIdentifier,
        code: u32,
        params: &ErrorParams,
    ) -> String {
        self._t_with_params(locale, &code_key(code), params)
    }

    #[must_use]
    pub fn fallback_locale(&self) -> &LanguageIdentifier {
        &self.fallback
    }

    #[must_use]
    pub fn loader(&self) -> Option<Arc<ArcLoader>> {
        self.loader.clone()
    }

    #[must_use]
    fn _t(&self, locale: &LanguageIdentifier, key: &str) -> String {
        self._t_with_args(locale, key, None)
    }

    #[must_use]
    fn _t_with_params(
        &self,
        locale: &LanguageIdentifier,
        key: &str,
        params: &ErrorParams,
    ) -> String {
        if params.is_empty() {
            return self._t(locale, key);
        }

        let args = params
            .iter()
            .map(|(key, value)| (Cow::Borrowed(key), FluentValue::from(value)))
            .collect::<HashMap<_, _>>();

        self._t_with_args(locale, key, Some(&args))
    }

    #[must_use]
    fn _t_with_args(
        &self,
        locale: &LanguageIdentifier,
        key: &str,
        args: Option<&HashMap<Cow<'static, str>, FluentValue<'_>>>,
    ) -> String {
        if let Some(loader) = &self.loader {
            match args {
                Some(args) => loader.lookup_with_args(locale, key, args),
                None => loader.lookup(locale, key),
            }
        } else {
            key.to_string()
        }
    }
}

fn code_key(code: u32) -> String {
    format!("E{code}")
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header::ACCEPT_LANGUAGE};
    use unic_langid::langid;

    use super::{I18n, resolve_locale_from_headers};

    #[test]
    fn resolve_locale_uses_primary_subtag_when_full_locale_is_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("fr-,en-US;q=0.8"));

        let locale = resolve_locale_from_headers(&headers);

        assert_eq!(locale, langid!("fr"));
    }

    #[test]
    fn resolve_locale_falls_back_to_english_when_header_is_missing() {
        let locale = resolve_locale_from_headers(&HeaderMap::new());

        assert_eq!(locale, langid!("en-US"));
    }

    #[test]
    fn disabled_i18n_returns_key_for_explicit_locale() {
        let i18n = I18n::disabled();

        assert_eq!(i18n.t(&langid!("en-US"), "auth-login"), "auth-login");
    }

    #[test]
    fn disabled_i18n_uses_explicit_locale_when_no_loader_is_configured() {
        let i18n = I18n::disabled();
        let translated = i18n.t(&langid!("zh-CN"), "welcome");

        assert_eq!(translated, "welcome");
    }
}
