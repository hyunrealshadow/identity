//! The port the instance sends email through.

use async_trait::async_trait;
use thiserror::Error;

use crate::setting::EmailDeliverySettings;

/// Data-protection purpose of the SMTP password and OAuth secrets kept in the
/// email delivery settings.
pub const EMAIL_DELIVERY_SECRET_PURPOSE: &str = "setting.email.delivery.secret";

pub use identity_domain::email::EmailMessage;

/// Why a message could not be delivered. `detail` is the mail server's or
/// token endpoint's own explanation, shown only to operators.
#[derive(Debug, Error)]
pub enum EmailDeliveryError {
    #[error("email delivery is not configured")]
    NotConfigured,
    #[error("invalid email address")]
    InvalidAddress,
    #[error("stored email delivery secret could not be read")]
    SecretUnavailable,
    #[error("authentication with the mail server failed: {detail}")]
    Authentication { detail: String },
    #[error("email delivery failed: {detail}")]
    Transport { detail: String },
}

impl EmailDeliveryError {
    /// A bounded, credential-free reason for diagnostics.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::InvalidAddress => "invalid_address",
            Self::SecretUnavailable => "secret_unavailable",
            Self::Authentication { .. } => "authentication_failed",
            Self::Transport { .. } => "transport_failed",
        }
    }

    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Authentication { detail } | Self::Transport { detail } => Some(detail),
            _ => None,
        }
    }
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Deliver `message` with `settings`. Callers pass the settings so an
    /// operator's test uses exactly what was just saved.
    async fn send(
        &self,
        settings: &EmailDeliverySettings,
        message: EmailMessage,
    ) -> Result<(), EmailDeliveryError>;
}
