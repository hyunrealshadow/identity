//! Email delivery and email template settings.

use serde::{Deserialize, Serialize};

use crate::{
    email::template::{
        EmailTemplateContent, EmailTemplates, MAX_BODY_LENGTH, MAX_SUBJECT_LENGTH,
        MAX_TEMPLATE_TRANSLATIONS,
    },
    setting::{SettingDefinition, SettingSection, SettingValidationError},
};

/// A secret kept in settings as a data-protection token (purpose
/// [`crate::email::EMAIL_DELIVERY_SECRET_PURPOSE`]), never as plaintext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtectedSecret(String);

impl ProtectedSecret {
    #[must_use]
    pub fn from_protected(token: String) -> Self {
        Self(token)
    }

    #[must_use]
    pub fn protected(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ProtectedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedSecret(..)")
    }
}

/// How the SMTP connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    /// TLS from the first byte (usually port 465).
    Tls,
    /// Plain connection upgraded with STARTTLS, which is required (usually
    /// port 587).
    #[default]
    StartTls,
    /// No transport security; only for a relay on a trusted network.
    None,
}

/// How an OAuth access token for XOAUTH2 is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Xoauth2Grant {
    /// Exchange a stored refresh token issued to the mailbox user.
    #[default]
    RefreshToken,
    /// Authenticate as the OAuth client itself.
    ClientCredentials,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xoauth2Settings {
    /// The mailbox the access token is for.
    pub username: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<ProtectedSecret>,
    pub grant: Xoauth2Grant,
    pub refresh_token: Option<ProtectedSecret>,
    /// Space-separated scopes requested with the token, if the provider needs them.
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SmtpAuthentication {
    /// An unauthenticated relay.
    #[default]
    None,
    /// `AUTH PLAIN` / `AUTH LOGIN` with a username and password.
    Password {
        username: String,
        password: ProtectedSecret,
    },
    /// `AUTH XOAUTH2` with an OAuth 2.0 access token.
    Xoauth2(Xoauth2Settings),
}

/// The SMTP server this instance sends email through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailDeliverySettings {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub sender_address: String,
    pub sender_name: Option<String>,
    pub authentication: SmtpAuthentication,
}

impl Default for EmailDeliverySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: 587,
            security: SmtpSecurity::StartTls,
            sender_address: String::new(),
            sender_name: None,
            authentication: SmtpAuthentication::None,
        }
    }
}

impl EmailDeliverySettings {
    /// Whether email can be sent at all.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.enabled && !self.host.trim().is_empty() && !self.sender_address.trim().is_empty()
    }
}

impl SettingSection for EmailDeliverySettings {
    const PREFIX: &'static str = "email.delivery";
    const OBJECT_FIELDS: &'static [&'static str] = &["authentication"];

    fn validate(&self) -> Result<(), SettingValidationError> {
        if self.port == 0 {
            return Err(SettingValidationError::new("SMTP port must not be zero"));
        }
        // Each stored field is checked against the defaults of the others, so
        // rules spanning several fields (an enabled server needs a host) are
        // enforced by the management command instead.
        if let SmtpAuthentication::Xoauth2(oauth) = &self.authentication
            && oauth.grant == Xoauth2Grant::RefreshToken
            && oauth.refresh_token.is_none()
        {
            return Err(SettingValidationError::new(
                "the refresh token grant needs a refresh token",
            ));
        }
        Ok(())
    }
}

/// Operator replacements of the built-in email templates.
pub struct EmailTemplatesSetting;

impl SettingDefinition for EmailTemplatesSetting {
    type Value = EmailTemplates;

    const KEY: &'static str = "email.templates";

    fn default_value() -> Self::Value {
        EmailTemplates::new()
    }

    fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
        let too_long = |content: &EmailTemplateContent| {
            content.subject.chars().count() > MAX_SUBJECT_LENGTH
                || content.html.chars().count() > MAX_BODY_LENGTH
        };
        for template in value.values() {
            if template.translations.len() > MAX_TEMPLATE_TRANSLATIONS {
                return Err(SettingValidationError::new(
                    "too many template translations",
                ));
            }
            if too_long(&template.default) || template.translations.values().any(too_long) {
                return Err(SettingValidationError::new("email template is too long"));
            }
            for locale in template.translations.keys() {
                if identity_domain::rbac::metadata::canonicalize_locale(locale).as_deref()
                    != Ok(locale.as_str())
                {
                    return Err(SettingValidationError::new(format!(
                        "invalid email template locale `{locale}`"
                    )));
                }
            }
        }
        Ok(())
    }
}
