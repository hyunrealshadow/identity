//! Outgoing email: how the instance delivers messages and the templates an
//! operator may localize for each kind of message.

pub mod compose;
pub mod delivery;
pub mod link;
pub mod template;

pub use compose::{EmailRecipient, TemplatedEmailError, send_templated_email};
pub use delivery::{EMAIL_DELIVERY_SECRET_PURPOSE, EmailDeliveryError, EmailMessage, EmailSender};
pub use link::{LinkToken, link_digest, link_matches, login_link_prefix, plausible_link_token};
pub use template::{
    EmailTemplate, EmailTemplateContent, EmailTemplateKind, EmailTemplatePart,
    EmailTemplateRenderError, EmailTemplateRenderer, EmailTemplates, RenderedEmail,
    built_in_template, effective_template,
};
