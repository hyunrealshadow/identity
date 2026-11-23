//! Email delivery over SMTP and rendering of email templates.

mod smtp;
mod template;

pub use smtp::SmtpEmailSender;
pub use template::TeraEmailTemplateRenderer;
