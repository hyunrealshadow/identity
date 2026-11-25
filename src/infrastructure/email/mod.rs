//! Email delivery over SMTP, the outgoing email queue, and rendering of
//! email templates.

pub mod queue;
mod smtp;
mod template;

pub use queue::{EMAIL_QUEUE, EmailJob, EmailQueue};
pub use smtp::SmtpEmailSender;
pub use template::TeraEmailTemplateRenderer;
