//! Composing one templated message: the template translation is chosen for
//! the recipient, the chosen locale is offered to the template, and the
//! result is ready to queue with the change that causes it.

use chrono::{DateTime, Utc};
use identity_domain::email::{EmailMessage, OutboundEmail};
use serde_json::Value;

use super::{
    EmailTemplateKind, EmailTemplateRenderError, EmailTemplateRenderer, EmailTemplates,
    effective_template,
};

/// Who a templated message goes to and in which languages, best first.
pub struct EmailRecipient<'a> {
    pub address: &'a str,
    pub name: Option<&'a str>,
    pub locales: &'a [&'a str],
}

/// Render the effective template of `kind` for `recipient`. `context`
/// receives the locale the message is written in; `expires_at` is when what
/// the message carries stops working.
pub fn render_templated_email(
    renderer: &dyn EmailTemplateRenderer,
    templates: &EmailTemplates,
    kind: EmailTemplateKind,
    recipient: EmailRecipient<'_>,
    expires_at: DateTime<Utc>,
    context: impl FnOnce(&str) -> Value,
) -> Result<OutboundEmail, EmailTemplateRenderError> {
    let (template, _) = effective_template(templates, kind);
    let (content, translation) = template.localize(recipient.locales.iter().copied());
    let locale = translation
        .or_else(|| recipient.locales.first().copied())
        .unwrap_or("en");
    let rendered = renderer.render(content, &context(locale))?;
    Ok(OutboundEmail {
        kind: kind.as_str(),
        message: EmailMessage {
            to_address: recipient.address.to_owned(),
            to_name: recipient.name.map(str::to_owned),
            subject: rendered.subject,
            html: rendered.html,
        },
        expires_at,
    })
}
