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
    use identity_application::email::{
        EmailTemplateKind, EmailTemplatePreviewScenario, built_in_template,
    };
    use serde_json::json;
    use strum::IntoEnumIterator;

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
        for kind in EmailTemplateKind::iter() {
            let template = built_in_template(kind);
            let languages = std::iter::once((&template.default, "en")).chain(
                template
                    .translations
                    .iter()
                    .map(|(tag, content)| (content, tag.as_str())),
            );
            for (content, locale) in languages {
                for context in kind.validation_contexts(locale) {
                    let rendered = TeraEmailTemplateRenderer.render(content, &context).unwrap();
                    assert!(!rendered.subject.is_empty());
                    assert!(!rendered.subject.contains('\n'));
                    assert!(!rendered.html.is_empty());
                }
            }
        }

        let sign_in = built_in_template(EmailTemplateKind::SignInCode);
        let with_app_en = TeraEmailTemplateRenderer
            .render(
                &sign_in.default,
                &EmailTemplateKind::SignInCode
                    .preview_context(
                        "en",
                        Some(EmailTemplatePreviewScenario::SignInCodeWithApplication),
                    )
                    .unwrap(),
            )
            .unwrap();
        assert!(!with_app_en.subject.contains("246810"));
        assert_eq!(with_app_en.subject, "Your sign-in code for Example App");
        assert!(with_app_en.html.contains("246810"));
        assert!(
            with_app_en
                .html
                .contains("https://login.example.com/login/email")
        );

        let without_app_en = TeraEmailTemplateRenderer
            .render(
                &sign_in.default,
                &EmailTemplateKind::SignInCode
                    .preview_context(
                        "en",
                        Some(EmailTemplatePreviewScenario::SignInCodeWithoutApplication),
                    )
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(without_app_en.subject, "Your sign-in code");

        let sign_in_zh = sign_in.translations.get("zh-CN").unwrap();
        let with_app_zh = TeraEmailTemplateRenderer
            .render(
                sign_in_zh,
                &EmailTemplateKind::SignInCode
                    .preview_context(
                        "zh-CN",
                        Some(EmailTemplatePreviewScenario::SignInCodeWithApplication),
                    )
                    .unwrap(),
            )
            .unwrap();
        assert!(!with_app_zh.subject.contains("246810"));
        assert_eq!(with_app_zh.subject, "登录 Example App 的验证码");
        let without_app_zh = TeraEmailTemplateRenderer
            .render(
                sign_in_zh,
                &EmailTemplateKind::SignInCode
                    .preview_context(
                        "zh-CN",
                        Some(EmailTemplatePreviewScenario::SignInCodeWithoutApplication),
                    )
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(without_app_zh.subject, "你的登录验证码");

        let registration = built_in_template(EmailTemplateKind::Registration);
        let new_account = TeraEmailTemplateRenderer
            .render(
                &registration.default,
                &EmailTemplateKind::Registration
                    .preview_context(
                        "en",
                        Some(EmailTemplatePreviewScenario::RegistrationNewAccount),
                    )
                    .unwrap(),
            )
            .unwrap();
        let existing_account = TeraEmailTemplateRenderer
            .render(
                &registration.default,
                &EmailTemplateKind::Registration
                    .preview_context(
                        "en",
                        Some(EmailTemplatePreviewScenario::RegistrationExistingAccount),
                    )
                    .unwrap(),
            )
            .unwrap();
        assert_ne!(new_account.subject, existing_account.subject);
        assert!(
            new_account
                .html
                .contains("https://login.example.com/login/register")
        );
        assert!(
            !existing_account
                .html
                .contains("https://login.example.com/login/register")
        );
        assert!(!new_account.html.contains("Example App"));
        assert!(!existing_account.html.contains("Example App"));

        let password_reset = built_in_template(EmailTemplateKind::PasswordReset);
        let reset_rendered = TeraEmailTemplateRenderer
            .render(
                &password_reset.default,
                &EmailTemplateKind::PasswordReset.sample_context("en"),
            )
            .unwrap();
        assert!(!reset_rendered.html.contains("Example App"));

        let verification = built_in_template(EmailTemplateKind::EmailVerification);
        let change_email = TeraEmailTemplateRenderer
            .render(
                &verification.default,
                &EmailTemplateKind::EmailVerification
                    .preview_context(
                        "en",
                        Some(EmailTemplatePreviewScenario::EmailVerificationChangeAddress),
                    )
                    .unwrap(),
            )
            .unwrap();
        let current_email = TeraEmailTemplateRenderer
            .render(
                &verification.default,
                &EmailTemplateKind::EmailVerification
                    .preview_context(
                        "en",
                        Some(EmailTemplatePreviewScenario::EmailVerificationCurrentAddress),
                    )
                    .unwrap(),
            )
            .unwrap();
        assert!(change_email.html.contains("alex.new@example.com"));
        assert!(!current_email.html.contains("alex.new@example.com"));
        assert!(current_email.html.contains("alex@example.com"));
    }
}
