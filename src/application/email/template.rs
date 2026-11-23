//! Localized email templates. Each kind of message has a built-in template per
//! supported locale; an operator may replace any of them. Templates use Tera
//! syntax and are rendered by an [`EmailTemplateRenderer`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

/// Locales every email template is available in. The first is the fallback.
pub const EMAIL_LOCALES: [&str; 2] = identity_domain::rbac::metadata::LANGUAGES;

pub const MAX_SUBJECT_LENGTH: usize = 500;
pub const MAX_BODY_LENGTH: usize = 100_000;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    strum::EnumIter,
)]
#[serde(rename_all = "snake_case")]
pub enum EmailTemplateKind {
    /// The one-time code and sign-in link of email sign-in.
    SignInCode,
}

impl EmailTemplateKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignInCode => "sign_in_code",
        }
    }

    /// Variables the template receives, as dotted paths.
    #[must_use]
    pub const fn variables(self) -> &'static [&'static str] {
        match self {
            Self::SignInCode => &[
                "code",
                "link",
                "expires_in_minutes",
                "user.name",
                "user.email",
                "application.name",
                "locale",
            ],
        }
    }

    /// Representative values for previews and for validating a template
    /// before it is saved.
    #[must_use]
    pub fn sample_context(self, locale: &str) -> Value {
        match self {
            Self::SignInCode => json!({
                "code": "246810",
                "link": "https://login.example.com/login/email?login_id=example&token=example",
                "expires_in_minutes": 10,
                "user": {
                    "name": if locale == "zh-CN" { "张三" } else { "Alex Doe" },
                    "email": "alex@example.com",
                },
                "application": { "name": "Example App" },
                "locale": locale,
            }),
        }
    }
}

/// The three parts of one localized template, as Tera source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailTemplateContent {
    pub subject: String,
    pub html: String,
    pub text: String,
}

/// Operator replacements: kind → locale → content. A locale that is absent
/// uses the built-in template.
pub type EmailTemplates = BTreeMap<EmailTemplateKind, BTreeMap<String, EmailTemplateContent>>;

/// The built-in template of `kind` in `locale` (a supported locale; any other
/// falls back to the first one).
#[must_use]
pub fn default_template(kind: EmailTemplateKind, locale: &str) -> EmailTemplateContent {
    let (subject, html, text) = match (kind, locale) {
        (EmailTemplateKind::SignInCode, "zh-CN") => (
            include_str!("templates/sign_in_code/zh-CN/subject.txt"),
            include_str!("templates/sign_in_code/zh-CN/body.html"),
            include_str!("templates/sign_in_code/zh-CN/body.txt"),
        ),
        (EmailTemplateKind::SignInCode, _) => (
            include_str!("templates/sign_in_code/en-US/subject.txt"),
            include_str!("templates/sign_in_code/en-US/body.html"),
            include_str!("templates/sign_in_code/en-US/body.txt"),
        ),
    };
    EmailTemplateContent {
        subject: subject.trim_end().to_owned(),
        html: html.to_owned(),
        text: text.to_owned(),
    }
}

/// The template to send for `kind` in `locale`, and whether an operator
/// replaced it.
#[must_use]
pub fn effective_template(
    templates: &EmailTemplates,
    kind: EmailTemplateKind,
    locale: &str,
) -> (EmailTemplateContent, bool) {
    templates
        .get(&kind)
        .and_then(|locales| locales.get(locale))
        .map_or_else(
            || (default_template(kind, locale), false),
            |content| (content.clone(), true),
        )
}

/// The first supported locale among `candidates` (exact, then by language),
/// or the fallback locale.
#[must_use]
pub fn select_locale<'a>(candidates: impl IntoIterator<Item = &'a str>) -> &'static str {
    let candidates: Vec<&str> = candidates.into_iter().map(str::trim).collect();
    for candidate in &candidates {
        if let Some(found) = EMAIL_LOCALES
            .iter()
            .find(|locale| locale.eq_ignore_ascii_case(&candidate.replace('_', "-")))
        {
            return found;
        }
    }
    for candidate in &candidates {
        let language = candidate.split(['-', '_']).next().unwrap_or_default();
        if language.is_empty() {
            continue;
        }
        if let Some(found) = EMAIL_LOCALES.iter().find(|locale| {
            locale
                .split('-')
                .next()
                .is_some_and(|own| own.eq_ignore_ascii_case(language))
        }) {
            return found;
        }
    }
    EMAIL_LOCALES[0]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    pub subject: String,
    pub html: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTemplatePart {
    Subject,
    Html,
    Text,
}

impl EmailTemplatePart {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Html => "html",
            Self::Text => "text",
        }
    }
}

/// A template that does not parse or render. `detail` is the template
/// engine's explanation, including the position of the problem.
#[derive(Debug, Clone, Error)]
#[error("email template {} failed to render: {detail}", part.as_str())]
pub struct EmailTemplateRenderError {
    pub part: EmailTemplatePart,
    pub detail: String,
}

pub trait EmailTemplateRenderer: Send + Sync {
    /// Render every part with `context`. The HTML body escapes values; the
    /// subject and text body do not. A rendered subject keeps a single line.
    fn render(
        &self,
        content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_a_supported_locale_exactly_then_by_language() {
        assert_eq!(select_locale(["fr-FR", "zh_cn"]), "zh-CN");
        assert_eq!(select_locale(["zh-TW"]), "zh-CN");
        assert_eq!(select_locale(["en-GB", "zh-CN"]), "zh-CN");
        assert_eq!(select_locale(["en-GB"]), "en-US");
        assert_eq!(select_locale(["de", ""]), "en-US");
    }

    #[test]
    fn an_operator_template_replaces_only_its_own_locale() {
        let custom = EmailTemplateContent {
            subject: "Code".to_owned(),
            html: "<p>{{ code }}</p>".to_owned(),
            text: "{{ code }}".to_owned(),
        };
        let templates = EmailTemplates::from([(
            EmailTemplateKind::SignInCode,
            BTreeMap::from([("zh-CN".to_owned(), custom.clone())]),
        )]);

        assert_eq!(
            effective_template(&templates, EmailTemplateKind::SignInCode, "zh-CN"),
            (custom, true)
        );
        let (english, customized) =
            effective_template(&templates, EmailTemplateKind::SignInCode, "en-US");
        assert!(!customized);
        assert_eq!(
            english,
            default_template(EmailTemplateKind::SignInCode, "en-US")
        );
    }
}
