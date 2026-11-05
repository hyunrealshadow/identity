use std::{
    borrow::Cow,
    collections::HashMap,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use fluent_templates::{ArcLoader, Loader, fluent_bundle::FluentValue};
use http::{HeaderMap, header::ACCEPT_LANGUAGE};
use identity_application::error::params::ErrorParams;
use unic_langid::{LanguageIdentifier, langid};

pub mod catalog;

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

/// Negotiate the only two supported request locales.
///
/// Compatible tags are normalized (`en`, `en-GB`, `en-*` -> `en-US`;
/// `zh`, `zh-Hans`, `zh-Hans-CN`, `zh-*` -> `zh-CN`). `q` weights are honored
/// (default `1.0`, highest first, stable on ties), `q=0` entries and malformed
/// or unsupported tags are ignored, and `en-US` is the fallback.
pub fn resolve_locale_from_headers(headers: &HeaderMap) -> LanguageIdentifier {
    let fallback = langid!("en-US");

    let Some(raw) = headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()) else {
        return fallback;
    };

    let mut best: Option<(f64, LanguageIdentifier)> = None;
    for part in raw.split(',') {
        let mut segments = part.split(';');
        let tag = segments.next().unwrap_or_default().trim();
        if tag.is_empty() {
            continue;
        }

        let mut weight = 1.0_f64;
        let mut malformed = false;
        for parameter in segments {
            let parameter = parameter.trim();
            if parameter.is_empty() {
                continue;
            }
            let Some((name, value)) = parameter.split_once('=') else {
                malformed = true;
                break;
            };
            if !name.trim().eq_ignore_ascii_case("q") {
                malformed = true;
                break;
            }
            match value.trim().parse::<f64>() {
                Ok(parsed) if parsed.is_finite() => weight = parsed,
                _ => {
                    malformed = true;
                    break;
                }
            }
        }
        if malformed || weight <= 0.0 {
            continue;
        }

        let Some(locale) = normalize_supported_locale(tag) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(best_weight, _)| weight > *best_weight)
        {
            best = Some((weight, locale));
        }
    }

    best.map_or(fallback, |(_, locale)| locale)
}

fn normalize_supported_locale(tag: &str) -> Option<LanguageIdentifier> {
    // Reject syntactically malformed tags (e.g. `fr-`) before normalizing.
    let parsed = LanguageIdentifier::from_str(tag).ok()?;
    match parsed.language.as_str() {
        "en" => Some(langid!("en-US")),
        "zh" => Some(langid!("zh-CN")),
        _ => None,
    }
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
    use std::collections::{BTreeMap, BTreeSet};

    use http::{HeaderMap, HeaderValue, header::ACCEPT_LANGUAGE};
    use unic_langid::langid;

    use super::{I18n, resolve_locale_from_headers};

    /// Every error catalog in both locales. Keep this list in sync with
    /// `assets/i18n/*/errors/`; the parity test covers the whole directory.
    const ERROR_CATALOGS: &[(&str, &str, &str)] = &[
        (
            "account",
            include_str!("../../../assets/i18n/en-US/errors/account.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/account.ftl"),
        ),
        (
            "auth",
            include_str!("../../../assets/i18n/en-US/errors/auth.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/auth.ftl"),
        ),
        (
            "authorization",
            include_str!("../../../assets/i18n/en-US/errors/authorization.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/authorization.ftl"),
        ),
        (
            "authorize",
            include_str!("../../../assets/i18n/en-US/errors/authorize.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/authorize.ftl"),
        ),
        (
            "authorize_http",
            include_str!("../../../assets/i18n/en-US/errors/authorize_http.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/authorize_http.ftl"),
        ),
        (
            "common",
            include_str!("../../../assets/i18n/en-US/errors/common.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/common.ftl"),
        ),
        (
            "data_protection",
            include_str!("../../../assets/i18n/en-US/errors/data_protection.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/data_protection.ftl"),
        ),
        (
            "device",
            include_str!("../../../assets/i18n/en-US/errors/device.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/device.ftl"),
        ),
        (
            "graphql",
            include_str!("../../../assets/i18n/en-US/errors/graphql.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/graphql.ftl"),
        ),
        (
            "graphql_transport",
            include_str!("../../../assets/i18n/en-US/errors/graphql_transport.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/graphql_transport.ftl"),
        ),
        (
            "client",
            include_str!("../../../assets/i18n/en-US/errors/client.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/client.ftl"),
        ),
        (
            "group",
            include_str!("../../../assets/i18n/en-US/errors/group.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/group.ftl"),
        ),
        (
            "install",
            include_str!("../../../assets/i18n/en-US/errors/install.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/install.ftl"),
        ),
        (
            "key",
            include_str!("../../../assets/i18n/en-US/errors/key.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/key.ftl"),
        ),
        (
            "oauth",
            include_str!("../../../assets/i18n/en-US/errors/oauth.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/oauth.ftl"),
        ),
        (
            "openid_connect",
            include_str!("../../../assets/i18n/en-US/errors/openid_connect.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/openid_connect.ftl"),
        ),
        (
            "provider",
            include_str!("../../../assets/i18n/en-US/errors/provider.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/provider.ftl"),
        ),
        (
            "registration",
            include_str!("../../../assets/i18n/en-US/errors/registration.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/registration.ftl"),
        ),
        (
            "token",
            include_str!("../../../assets/i18n/en-US/errors/token.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/token.ftl"),
        ),
        (
            "user_management",
            include_str!("../../../assets/i18n/en-US/errors/user_management.ftl"),
            include_str!("../../../assets/i18n/zh-CN/errors/user_management.ftl"),
        ),
    ];

    fn parse_catalog(source: &str) -> BTreeMap<String, BTreeSet<String>> {
        let mut entries = BTreeMap::new();
        let mut current: Option<String> = None;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = split_entry(line) {
                let mut params = BTreeSet::new();
                collect_params(value, &mut params);
                entries.insert(key.clone(), params);
                current = Some(key);
            } else if line.starts_with(|character: char| character.is_whitespace()) {
                if let Some(key) = &current
                    && let Some(params) = entries.get_mut(key)
                {
                    collect_params(line, params);
                }
            } else {
                current = None;
            }
        }
        entries
    }

    fn split_entry(line: &str) -> Option<(String, &str)> {
        if line.starts_with(|character: char| character.is_whitespace()) {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        let key = key.trim();
        let digits = key.strip_prefix('E')?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some((key.to_owned(), value))
    }

    fn collect_params(text: &str, params: &mut BTreeSet<String>) {
        let mut rest = text;
        while let Some(index) = rest.find('$') {
            let after = &rest[index + 1..];
            let name = after
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect::<String>();
            if !name.is_empty() {
                params.insert(name);
            }
            rest = after;
        }
    }

    fn compare_catalog(module: &str, en: &str, zh: &str) -> Result<(), String> {
        let en_entries = parse_catalog(en);
        let zh_entries = parse_catalog(zh);
        for key in en_entries.keys() {
            if !zh_entries.contains_key(key) {
                return Err(format!("{module}: zh-CN is missing {key}"));
            }
        }
        for key in zh_entries.keys() {
            if !en_entries.contains_key(key) {
                return Err(format!("{module}: en-US is missing {key}"));
            }
        }
        for (key, en_params) in &en_entries {
            let Some(zh_params) = zh_entries.get(key) else {
                continue;
            };
            if en_params != zh_params {
                return Err(format!(
                    "{module}: {key} parameter mismatch: en-US {en_params:?} vs zh-CN {zh_params:?}"
                ));
            }
        }
        Ok(())
    }

    fn assert_catalog_parity() -> Result<(), String> {
        for (module, en, zh) in ERROR_CATALOGS {
            compare_catalog(module, en, zh)?;
        }
        Ok(())
    }

    #[test]
    fn resolve_locale_normalizes_english_variants() {
        for tag in ["en", "en-GB", "en-AU", "en-US"] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_str(tag).unwrap());
            assert_eq!(resolve_locale_from_headers(&headers), langid!("en-US"));
        }
    }

    #[test]
    fn resolve_locale_normalizes_chinese_variants() {
        for tag in ["zh", "zh-Hans", "zh-Hans-CN", "zh-CN", "zh-TW"] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_str(tag).unwrap());
            assert_eq!(resolve_locale_from_headers(&headers), langid!("zh-CN"));
        }
    }

    #[test]
    fn resolve_locale_honors_quality_weights() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US;q=0.4, zh-CN;q=0.9, fr;q=1.0"),
        );
        assert_eq!(resolve_locale_from_headers(&headers), langid!("zh-CN"));
    }

    #[test]
    fn resolve_locale_is_stable_on_ties_and_skips_zero_weight() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("zh-CN;q=0.5, en-US;q=0.5"),
        );
        assert_eq!(resolve_locale_from_headers(&headers), langid!("zh-CN"));

        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("zh-CN;q=0, en-US;q=0.1"),
        );
        assert_eq!(resolve_locale_from_headers(&headers), langid!("en-US"));
    }

    #[test]
    fn resolve_locale_ignores_malformed_and_unsupported_tags() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("fr-,fr;q=0.9,*,de;q=1.0,en-GB;q=0.2"),
        );
        assert_eq!(resolve_locale_from_headers(&headers), langid!("en-US"));
    }

    #[test]
    fn resolve_locale_falls_back_to_english_when_header_is_missing() {
        let locale = resolve_locale_from_headers(&HeaderMap::new());

        assert_eq!(locale, langid!("en-US"));
    }

    #[test]
    fn error_catalogs_have_identical_keys_and_params() {
        assert_catalog_parity().expect("error catalogs must stay in parity");
    }

    #[test]
    fn parity_check_rejects_a_missing_key() {
        let error = compare_catalog("synthetic", "E1 = Present\n", "E2 = 缺失\n")
            .expect_err("missing key must fail");

        assert!(error.contains("missing"), "{error}");
    }

    #[test]
    fn parity_check_rejects_a_mismatched_parameter() {
        let error = compare_catalog(
            "synthetic",
            "E1 = Hello { $name }\n",
            "E1 = 你好 { $other }\n",
        )
        .expect_err("mismatched parameter must fail");

        assert!(error.contains("parameter mismatch"), "{error}");
    }

    #[test]
    fn disabled_i18n_returns_key_for_explicit_locale() {
        let i18n = I18n::disabled();

        assert_eq!(i18n.t(&langid!("en-US"), "auth-login"), "auth-login");
    }
}
