//! Composing one templated message: the template translation is chosen for
//! the recipient, the chosen locale is offered to the template, and the
//! result is sent.

use serde_json::Value;

use super::{
    EmailDeliveryError, EmailMessage, EmailSender, EmailTemplateKind, EmailTemplateRenderError,
    EmailTemplateRenderer, EmailTemplates, effective_template,
};
use crate::setting::EmailDeliverySettings;

/// Who a templated message goes to and in which languages, best first.
pub struct EmailRecipient<'a> {
    pub address: &'a str,
    pub name: Option<&'a str>,
    pub locales: &'a [&'a str],
}

/// Why a templated message was not sent.
#[derive(Debug, thiserror::Error)]
pub enum TemplatedEmailError {
    #[error(transparent)]
    Render(#[from] EmailTemplateRenderError),
    #[error(transparent)]
    Delivery(#[from] EmailDeliveryError),
}

impl TemplatedEmailError {
    /// A bounded, credential-free reason for diagnostics.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Render(_) => "template_failed",
            Self::Delivery(error) => error.reason(),
        }
    }
}

/// Render the effective template of `kind` for `recipient` and send it.
/// `context` receives the locale the message is written in.
pub async fn send_templated_email(
    sender: &dyn EmailSender,
    renderer: &dyn EmailTemplateRenderer,
    delivery: &EmailDeliverySettings,
    templates: &EmailTemplates,
    kind: EmailTemplateKind,
    recipient: EmailRecipient<'_>,
    context: impl FnOnce(&str) -> Value,
) -> Result<(), TemplatedEmailError> {
    let (template, _) = effective_template(templates, kind);
    let (content, translation) = template.localize(recipient.locales.iter().copied());
    let locale = translation
        .or_else(|| recipient.locales.first().copied())
        .unwrap_or("en");
    let rendered = renderer.render(content, &context(locale))?;
    sender
        .send(
            delivery,
            EmailMessage {
                to_address: recipient.address.to_owned(),
                to_name: recipient.name.map(str::to_owned),
                subject: rendered.subject,
                html: rendered.html,
            },
        )
        .await?;
    Ok(())
}
