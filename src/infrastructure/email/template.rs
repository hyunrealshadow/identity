//! Tera rendering of operator-editable email templates.
//!
//! Each render uses a fresh engine that holds only the template being
//! rendered, so a template cannot include another, and it registers no
//! function beyond Tera's own built-ins (which read neither files nor the
//! environment).

use std::error::Error as StdError;

use identity_application::email::{
    EmailTemplateContent, EmailTemplatePart, EmailTemplateRenderError, EmailTemplateRenderer,
    RenderedEmail,
};
use serde_json::Value;
use tera::{Context, Tera};

/// Longest explanation returned for a template that fails to render.
const MAX_DETAIL_LENGTH: usize = 500;

#[derive(Debug, Default, Clone, Copy)]
pub struct TeraEmailTemplateRenderer;

fn detail(error: &tera::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(next) = source {
        let text = next.to_string();
        if !parts.contains(&text) {
            parts.push(text);
        }
        source = next.source();
    }
    let joined = parts.join(": ");
    let mut detail: String = joined.chars().take(MAX_DETAIL_LENGTH).collect();
    if joined.chars().count() > MAX_DETAIL_LENGTH {
        detail.push('…');
    }
    detail
}

fn render_part(
    engine: &Tera,
    source: &str,
    context: &Context,
    part: EmailTemplatePart,
) -> Result<String, EmailTemplateRenderError> {
    engine
        .render_str(source, context, part == EmailTemplatePart::Html)
        .map_err(|error| EmailTemplateRenderError {
            part,
            detail: detail(&error),
        })
}

impl EmailTemplateRenderer for TeraEmailTemplateRenderer {
    fn render(
        &self,
        content: &EmailTemplateContent,
        context: &Value,
    ) -> Result<RenderedEmail, EmailTemplateRenderError> {
        let engine = Tera::default();
        let context =
            Context::from_serialize(context).map_err(|error| EmailTemplateRenderError {
                part: EmailTemplatePart::Subject,
                detail: detail(&error),
            })?;
        let subject = render_part(
            &engine,
            &content.subject,
            &context,
            EmailTemplatePart::Subject,
        )?;
        Ok(RenderedEmail {
            // A header holds one line.
            subject: subject.split_whitespace().collect::<Vec<_>>().join(" "),
            html: render_part(&engine, &content.html, &context, EmailTemplatePart::Html)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use identity_application::email::{EmailTemplateKind, built_in_template};
    use serde_json::json;

    use super::*;

    fn content(subject: &str, html: &str) -> EmailTemplateContent {
        EmailTemplateContent {
            subject: subject.to_owned(),
            html: html.to_owned(),
        }
    }

    #[test]
    fn escapes_values_only_in_the_html_body() {
        let rendered = TeraEmailTemplateRenderer
            .render(
                &content("Hi {{ name }}\n again", "<p>{{ name }}</p>"),
                &json!({ "name": "<b>Ann & Bo</b>" }),
            )
            .unwrap();

        assert_eq!(rendered.subject, "Hi <b>Ann & Bo</b> again");
        assert_eq!(rendered.html, "<p>&lt;b&gt;Ann &amp; Bo&lt;/b&gt;</p>");
    }

    #[test]
    fn reports_the_part_that_fails() {
        let error = TeraEmailTemplateRenderer
            .render(&content("ok", "<p>{% if %}</p>"), &json!({}))
            .unwrap_err();
        assert_eq!(error.part, EmailTemplatePart::Html);
        assert!(!error.detail.is_empty());

        let missing = TeraEmailTemplateRenderer
            .render(&content("{{ missing.value }}", "ok"), &json!({}))
            .unwrap_err();
        assert_eq!(missing.part, EmailTemplatePart::Subject);
    }

    #[test]
    fn templates_cannot_include_other_templates() {
        let error = TeraEmailTemplateRenderer
            .render(&content("ok", "{% include \"config\" %}"), &json!({}))
            .unwrap_err();
        assert_eq!(error.part, EmailTemplatePart::Html);
    }

    #[test]
    fn built_in_templates_render_with_their_sample_values() {
        let kind = EmailTemplateKind::SignInCode;
        let template = built_in_template(kind);
        let languages = std::iter::once((&template.default, "en")).chain(
            template
                .translations
                .iter()
                .map(|(tag, content)| (content, tag.as_str())),
        );
        for (content, locale) in languages {
            let rendered = TeraEmailTemplateRenderer
                .render(content, &kind.sample_context(locale))
                .unwrap();
            assert!(rendered.subject.contains("246810"));
            assert!(rendered.html.contains("246810"));
            assert!(
                rendered
                    .html
                    .contains("https://login.example.com/login/email")
            );
            assert!(!rendered.subject.contains('\n'));
        }
        let mut without_application = kind.sample_context("en");
        without_application["application"] = Value::Null;
        let rendered = TeraEmailTemplateRenderer
            .render(&template.default, &without_application)
            .unwrap();
        assert_eq!(rendered.subject, "246810 is your sign-in code");
    }
}
