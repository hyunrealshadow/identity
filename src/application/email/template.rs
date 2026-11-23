//! Localized email templates. Like other localized text, each kind of message
//! has default content, used when no translation fits the reader, and
//! optional translations keyed by language tag. Every kind ships a built-in
//! template; an operator may replace it with their own. Templates use Tera
//! syntax and are rendered by an [`EmailTemplateRenderer`].

use std::collections::BTreeMap;

use identity_domain::rbac::metadata::{MAX_LOCALIZED_ENTRIES, canonicalize_locale};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

pub const MAX_SUBJECT_LENGTH: usize = 500;
pub const MAX_BODY_LENGTH: usize = 100_000;
/// Translations one template may carry, as for other localized text.
pub const MAX_TEMPLATE_TRANSLATIONS: usize = MAX_LOCALIZED_ENTRIES;

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
    /// before it is saved. `locale` is the language being previewed.
    #[must_use]
    pub fn sample_context(self, locale: &str) -> Value {
        let chinese = locale.split('-').next() == Some("zh");
        match self {
            Self::SignInCode => json!({
                "code": "246810",
                "link": "https://login.example.com/login/email?login_id=example&token=example",
                "expires_in_minutes": 10,
                "user": {
                    "name": if chinese { "张三" } else { "Alex Doe" },
                    "email": "alex@example.com",
                },
                "application": { "name": "Example App" },
                "locale": locale,
            }),
        }
    }
}

/// One language of a template, as Tera source. The plain-text alternative
/// of a message is derived from its HTML body when it is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailTemplateContent {
    pub subject: String,
    pub html: String,
}

/// One template: default content and its translations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailTemplate {
    pub default: EmailTemplateContent,
    /// Canonical language tag → content.
    #[serde(default)]
    pub translations: BTreeMap<String, EmailTemplateContent>,
}

impl EmailTemplate {
    /// The content for a reader who prefers `candidates`, most preferred
    /// first, and the language tag of the translation used. Each candidate is
    /// matched exactly, then by its language; the default content is used
    /// when none matches.
    #[must_use]
    pub fn localize<'a, 'c>(
        &'a self,
        candidates: impl IntoIterator<Item = &'c str>,
    ) -> (&'a EmailTemplateContent, Option<&'a str>) {
        let candidates: Vec<String> = candidates
            .into_iter()
            .filter_map(|candidate| canonicalize_locale(candidate).ok())
            .collect();
        let found = candidates
            .iter()
            .find_map(|candidate| self.translations.get_key_value(candidate))
            .or_else(|| {
                candidates.iter().find_map(|candidate| {
                    let language = candidate.split('-').next()?;
                    self.translations
                        .iter()
                        .find(|(tag, _)| tag.split('-').next() == Some(language))
                })
            });
        match found {
            Some((tag, content)) => (content, Some(tag.as_str())),
            None => (&self.default, None),
        }
    }
}

/// Operator templates by kind. A kind that is absent uses its built-in
/// template.
pub type EmailTemplates = BTreeMap<EmailTemplateKind, EmailTemplate>;

fn content(subject: &str, html: &str) -> EmailTemplateContent {
    EmailTemplateContent {
        subject: subject.trim_end().to_owned(),
        html: html.to_owned(),
    }
}

/// The template shipped for `kind`.
#[must_use]
pub fn built_in_template(kind: EmailTemplateKind) -> EmailTemplate {
    match kind {
        EmailTemplateKind::SignInCode => EmailTemplate {
            default: content(
                include_str!("templates/sign_in_code/en-US/subject.txt"),
                include_str!("templates/sign_in_code/en-US/body.html"),
            ),
            translations: BTreeMap::from([(
                "zh-CN".to_owned(),
                content(
                    include_str!("templates/sign_in_code/zh-CN/subject.txt"),
                    include_str!("templates/sign_in_code/zh-CN/body.html"),
                ),
            )]),
        },
    }
}

/// The template sent for `kind`, and whether an operator replaced it.
#[must_use]
pub fn effective_template(
    templates: &EmailTemplates,
    kind: EmailTemplateKind,
) -> (EmailTemplate, bool) {
    templates.get(&kind).map_or_else(
        || (built_in_template(kind), false),
        |template| (template.clone(), true),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    pub subject: String,
    pub html: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTemplatePart {
    Subject,
    Html,
}

impl EmailTemplatePart {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Html => "html",
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
    /// subject does not, and keeps a single line.
    fn render(
        &self,
        content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> EmailTemplate {
        let text = |value: &str| content(value, value);
        EmailTemplate {
            default: text("default"),
            translations: BTreeMap::from([
                ("zh-CN".to_owned(), text("zh-CN")),
                ("pt-BR".to_owned(), text("pt-BR")),
            ]),
        }
    }

    #[test]
    fn a_reader_gets_the_closest_translation_or_the_default() {
        let template = template();
        let subject = |candidates: &[&str]| {
            let (content, tag) = template.localize(candidates.iter().copied());
            (content.subject.clone(), tag.map(str::to_owned))
        };
        assert_eq!(subject(&["zh_cn"]), ("zh-CN".into(), Some("zh-CN".into())));
        // Exact tags win over an earlier candidate's language.
        assert_eq!(
            subject(&["zh-TW", "pt-BR"]),
            ("pt-BR".into(), Some("pt-BR".into()))
        );
        assert_eq!(subject(&["zh-TW"]), ("zh-CN".into(), Some("zh-CN".into())));
        assert_eq!(subject(&["pt-PT"]), ("pt-BR".into(), Some("pt-BR".into())));
        assert_eq!(subject(&["de-DE", "not a tag"]), ("default".into(), None));
        assert_eq!(subject(&[]), ("default".into(), None));
    }

    #[test]
    fn an_operator_template_replaces_the_built_in_one() {
        let kind = EmailTemplateKind::SignInCode;
        let (built_in, customized) = effective_template(&EmailTemplates::new(), kind);
        assert!(!customized);
        assert!(built_in.translations.contains_key("zh-CN"));

        let templates = EmailTemplates::from([(kind, template())]);
        assert_eq!(effective_template(&templates, kind), (template(), true));
    }
}
