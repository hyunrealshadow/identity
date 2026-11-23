//! Outgoing email: how the instance delivers messages and the templates an
//! operator may localize for each kind of message.

pub mod delivery;
pub mod template;

pub use delivery::{EMAIL_DELIVERY_SECRET_PURPOSE, EmailDeliveryError, EmailMessage, EmailSender};
pub use template::{
    EMAIL_LOCALES, EmailTemplateContent, EmailTemplateKind, EmailTemplatePart,
    EmailTemplateRenderError, EmailTemplateRenderer, EmailTemplates, RenderedEmail,
    default_template, select_locale,
};
