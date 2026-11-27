//! Email delivery, email policy, and email template settings.

use std::time::Duration;

use identity_domain::auth::challenge::DeliveryPolicy;
use serde::{Deserialize, Serialize};

use crate::{
    email::template::{
        EmailTemplateContent, EmailTemplates, MAX_BODY_LENGTH, MAX_SUBJECT_LENGTH,
        MAX_TEMPLATE_TRANSLATIONS,
    },
    setting::{SettingDefinition, SettingSection, SettingValidationError},
};

/// A secret kept in email delivery settings, redacted in `Debug` and never
/// returned by management views.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EmailSecret(String);

impl EmailSecret {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EmailSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmailSecret(..)")
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
    pub client_secret: Option<EmailSecret>,
    pub grant: Xoauth2Grant,
    pub refresh_token: Option<EmailSecret>,
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
        password: EmailSecret,
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

/// Lifetimes, resend cadence, and send limits for outbound system emails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailPolicySettings {
    pub sign_in_code_lifetime_minutes: u32,
    pub password_reset_lifetime_minutes: u32,
    pub registration_lifetime_minutes: u32,
    pub email_verification_lifetime_hours: u32,
    pub user_invitation_lifetime_days: u32,
    pub resend_interval_seconds: u32,
    pub login_max_sends: u32,
    pub verification_max_sends: u32,
    pub verification_send_window_hours: u32,
}

impl Default for EmailPolicySettings {
    fn default() -> Self {
        Self {
            sign_in_code_lifetime_minutes: 10,
            password_reset_lifetime_minutes: 15,
            registration_lifetime_minutes: 15,
            email_verification_lifetime_hours: 24,
            user_invitation_lifetime_days: 7,
            resend_interval_seconds: 60,
            login_max_sends: 5,
            verification_max_sends: 5,
            verification_send_window_hours: 24,
        }
    }
}

impl EmailPolicySettings {
    #[must_use]
    pub const fn sign_in_code_lifetime(&self) -> Duration {
        Duration::from_secs(self.sign_in_code_lifetime_minutes as u64 * 60)
    }

    #[must_use]
    pub const fn password_reset_lifetime(&self) -> Duration {
        Duration::from_secs(self.password_reset_lifetime_minutes as u64 * 60)
    }

    #[must_use]
    pub const fn registration_lifetime(&self) -> Duration {
        Duration::from_secs(self.registration_lifetime_minutes as u64 * 60)
    }

    #[must_use]
    pub const fn email_verification_lifetime(&self) -> Duration {
        Duration::from_secs(self.email_verification_lifetime_hours as u64 * 3_600)
    }

    #[must_use]
    pub const fn user_invitation_lifetime(&self) -> Duration {
        Duration::from_secs(self.user_invitation_lifetime_days as u64 * 86_400)
    }

    #[must_use]
    pub const fn resend_interval(&self) -> Duration {
        Duration::from_secs(self.resend_interval_seconds as u64)
    }

    #[must_use]
    pub fn login_delivery_policy(&self) -> DeliveryPolicy {
        DeliveryPolicy {
            resend_interval: self.resend_interval(),
            max_sends: Some(i32::try_from(self.login_max_sends).unwrap_or(5)),
            window: None,
        }
    }

    #[must_use]
    pub fn verification_delivery_policy(&self) -> DeliveryPolicy {
        DeliveryPolicy {
            resend_interval: self.resend_interval(),
            max_sends: Some(i32::try_from(self.verification_max_sends).unwrap_or(5)),
            window: Some(Duration::from_secs(
                u64::from(self.verification_send_window_hours) * 3_600,
            )),
        }
    }

    #[must_use]
    pub const fn invitation_delivery_policy(&self) -> DeliveryPolicy {
        DeliveryPolicy {
            resend_interval: self.resend_interval(),
            max_sends: None,
            window: None,
        }
    }
}

impl SettingSection for EmailPolicySettings {
    const PREFIX: &'static str = "email.policy";
    const OBJECT_FIELDS: &'static [&'static str] = &[];

    fn validate(&self) -> Result<(), SettingValidationError> {
        if !(1..=60).contains(&self.sign_in_code_lifetime_minutes) {
            return Err(SettingValidationError::new(
                "sign-in code lifetime must be between 1 and 60 minutes",
            ));
        }
        if !(5..=120).contains(&self.password_reset_lifetime_minutes) {
            return Err(SettingValidationError::new(
                "password reset link lifetime must be between 5 and 120 minutes",
            ));
        }
        if !(5..=120).contains(&self.registration_lifetime_minutes) {
            return Err(SettingValidationError::new(
                "registration link lifetime must be between 5 and 120 minutes",
            ));
        }
        if !(1..=168).contains(&self.email_verification_lifetime_hours) {
            return Err(SettingValidationError::new(
                "email verification link lifetime must be between 1 and 168 hours",
            ));
        }
        if !(1..=30).contains(&self.user_invitation_lifetime_days) {
            return Err(SettingValidationError::new(
                "user invitation lifetime must be between 1 and 30 days",
            ));
        }
        if !(15..=600).contains(&self.resend_interval_seconds) {
            return Err(SettingValidationError::new(
                "email resend interval must be between 15 and 600 seconds",
            ));
        }
        if !(1..=20).contains(&self.login_max_sends) {
            return Err(SettingValidationError::new(
                "maximum emails per sign-in flow must be between 1 and 20",
            ));
        }
        if !(1..=20).contains(&self.verification_max_sends) {
            return Err(SettingValidationError::new(
                "maximum verification emails per window must be between 1 and 20",
            ));
        }
        if !(1..=168).contains(&self.verification_send_window_hours) {
            return Err(SettingValidationError::new(
                "verification send window must be between 1 and 168 hours",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_policy_defaults_and_durations_match_baseline() {
        let policy = EmailPolicySettings::default();
        assert!(policy.validate().is_ok());
        assert_eq!(policy.sign_in_code_lifetime(), Duration::from_secs(10 * 60));
        assert_eq!(
            policy.password_reset_lifetime(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(policy.registration_lifetime(), Duration::from_secs(15 * 60));
        assert_eq!(
            policy.email_verification_lifetime(),
            Duration::from_secs(24 * 3_600)
        );
        assert_eq!(
            policy.user_invitation_lifetime(),
            Duration::from_secs(7 * 86_400)
        );
        assert_eq!(policy.resend_interval(), Duration::from_secs(60));
        assert_eq!(policy.login_delivery_policy().max_sends, Some(5));
        assert_eq!(
            policy.verification_delivery_policy().window,
            Some(Duration::from_secs(24 * 3_600))
        );
        assert_eq!(policy.invitation_delivery_policy().max_sends, None);
    }

    #[test]
    fn email_policy_rejects_out_of_bounds_values() {
        let valid = EmailPolicySettings::default();
        let invalid_cases = [
            EmailPolicySettings {
                sign_in_code_lifetime_minutes: 0,
                ..valid
            },
            EmailPolicySettings {
                password_reset_lifetime_minutes: 4,
                ..valid
            },
            EmailPolicySettings {
                registration_lifetime_minutes: 121,
                ..valid
            },
            EmailPolicySettings {
                email_verification_lifetime_hours: 169,
                ..valid
            },
            EmailPolicySettings {
                user_invitation_lifetime_days: 31,
                ..valid
            },
            EmailPolicySettings {
                resend_interval_seconds: 14,
                ..valid
            },
            EmailPolicySettings {
                login_max_sends: 21,
                ..valid
            },
            EmailPolicySettings {
                verification_max_sends: 0,
                ..valid
            },
            EmailPolicySettings {
                verification_send_window_hours: 0,
                ..valid
            },
        ];
        for invalid in invalid_cases {
            assert!(invalid.validate().is_err());
        }
    }
}
