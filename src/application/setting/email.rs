//! Email delivery and email template management.
//!
//! Delivery is one versioned section; each template kind is another, holding
//! every locale of that kind. Secrets are protected before the write and are
//! never returned: a view only says whether one is stored. Leaving a secret
//! out of an update keeps the stored one while the method stays the same.

use std::{collections::BTreeMap, sync::Arc};

use serde_json::Value;
use sha2::{Digest, Sha256};
use strum::IntoEnumIterator;
use url::Url;
use uuid::Uuid;
use validator::ValidateEmail;

use super::{
    EmailDeliverySettings, EmailTemplatesSetting, ProtectedSecret, SettingChanges,
    SmtpAuthentication, SmtpSecurity, Xoauth2Grant, Xoauth2Settings,
    management::{
        InstanceSettingSection, InstanceSettingService, InstanceSettingsState,
        InstanceSettingsView, SettingRange, map_repository_error, validate_client_mutation_id,
    },
};
use crate::{
    data_protection::DataProtector,
    email::{
        EMAIL_DELIVERY_SECRET_PURPOSE, EmailMessage, EmailSender, EmailTemplate,
        EmailTemplateContent, EmailTemplateKind, EmailTemplateRenderError, EmailTemplateRenderer,
        RenderedEmail, built_in_template, effective_template,
        template::{MAX_BODY_LENGTH, MAX_SUBJECT_LENGTH, MAX_TEMPLATE_TRANSLATIONS},
    },
    error::{AppError, codes::instance::InstanceErrorCode},
    observability::{BusinessEvent, EventValue},
    rbac::RbacManagementAuthority,
};

pub const SMTP_PORT_RANGE: SettingRange = SettingRange {
    min: 1,
    max: 65_535,
};
const MAX_HOST_LENGTH: usize = 253;
const MAX_FIELD_LENGTH: usize = 2_048;
const MAX_SECRET_LENGTH: usize = 8_192;

/// What email management needs besides settings storage.
#[derive(Clone)]
pub struct EmailManagementDependencies {
    pub protector: Arc<dyn DataProtector>,
    pub renderer: Arc<dyn EmailTemplateRenderer>,
    pub sender: Arc<dyn EmailSender>,
}

// ─── Views ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailAuthenticationMethod {
    None,
    Password,
    Xoauth2,
}

/// SMTP authentication as an operator sees it: secrets only as "stored".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAuthenticationView {
    pub method: EmailAuthenticationMethod,
    pub username: Option<String>,
    pub password_set: bool,
    pub token_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_set: bool,
    pub grant: Option<Xoauth2Grant>,
    pub refresh_token_set: bool,
    pub scope: Option<String>,
}

impl From<&SmtpAuthentication> for EmailAuthenticationView {
    fn from(authentication: &SmtpAuthentication) -> Self {
        let none = Self {
            method: EmailAuthenticationMethod::None,
            username: None,
            password_set: false,
            token_endpoint: None,
            client_id: None,
            client_secret_set: false,
            grant: None,
            refresh_token_set: false,
            scope: None,
        };
        match authentication {
            SmtpAuthentication::None => none,
            SmtpAuthentication::Password { username, .. } => Self {
                method: EmailAuthenticationMethod::Password,
                username: Some(username.clone()),
                password_set: true,
                ..none
            },
            SmtpAuthentication::Xoauth2(oauth) => Self {
                method: EmailAuthenticationMethod::Xoauth2,
                username: Some(oauth.username.clone()),
                token_endpoint: Some(oauth.token_endpoint.clone()),
                client_id: Some(oauth.client_id.clone()),
                client_secret_set: oauth.client_secret.is_some(),
                grant: Some(oauth.grant),
                refresh_token_set: oauth.refresh_token.is_some(),
                scope: oauth.scope.clone(),
                ..none
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailDeliveryView {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub sender_address: String,
    pub sender_name: Option<String>,
    pub authentication: EmailAuthenticationView,
    /// Enabled with a server and a sender: email can be sent.
    pub configured: bool,
    pub version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTemplateView {
    pub kind: EmailTemplateKind,
    pub variables: &'static [&'static str],
    /// Whether an operator replaced the built-in template.
    pub customized: bool,
    /// The template that is sent.
    pub template: EmailTemplate,
    pub built_in: EmailTemplate,
    pub version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailSettingsView {
    pub delivery: EmailDeliveryView,
    pub templates: Vec<EmailTemplateView>,
}

impl From<&InstanceSettingsState> for EmailSettingsView {
    fn from(state: &InstanceSettingsState) -> Self {
        let delivery = &state.email_delivery;
        Self {
            delivery: EmailDeliveryView {
                enabled: delivery.enabled,
                host: delivery.host.clone(),
                port: delivery.port,
                security: delivery.security,
                sender_address: delivery.sender_address.clone(),
                sender_name: delivery.sender_name.clone(),
                authentication: EmailAuthenticationView::from(&delivery.authentication),
                configured: delivery.is_configured(),
                version: InstanceSettingSection::Email.version(state),
            },
            templates: EmailTemplateKind::iter()
                .map(|kind| {
                    let (template, customized) = effective_template(&state.email_templates, kind);
                    EmailTemplateView {
                        kind,
                        variables: kind.variables(),
                        customized,
                        template,
                        built_in: built_in_template(kind),
                        version: InstanceSettingSection::EmailTemplate(kind).version(state),
                    }
                })
                .collect(),
        }
    }
}

/// The delivery settings as audited: secrets become a fingerprint of their
/// protected form, so a replacement is visible without exposing anything.
#[must_use]
pub fn email_delivery_audit_values(settings: &EmailDeliverySettings) -> Value {
    fn fingerprint(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for (name, field) in fields.iter_mut() {
                    if matches!(
                        name.as_str(),
                        "password" | "client_secret" | "refresh_token"
                    ) && let Value::String(token) = field
                    {
                        let digest = Sha256::digest(token.as_bytes());
                        let hex = digest[..6]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>();
                        *field = Value::String(format!("protected:{hex}"));
                    } else {
                        fingerprint(field);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(fingerprint),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(settings).unwrap_or(Value::Null);
    fingerprint(&mut value);
    value
}

/// One template kind as audited: the subject of its default content and of
/// each translation, and a digest of each body rather than the body itself.
#[must_use]
pub fn email_template_audit_values(template: Option<&EmailTemplate>) -> Value {
    fn digest(value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        let hex = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("sha256:{hex}")
    }
    fn content(content: &EmailTemplateContent) -> Value {
        serde_json::json!({
            "subject": content.subject,
            "html": digest(&content.html),
        })
    }
    template.map_or(Value::Null, |template| {
        serde_json::json!({
            "default": content(&template.default),
            "translations": template
                .translations
                .iter()
                .map(|(locale, translation)| (locale.clone(), content(translation)))
                .collect::<serde_json::Map<_, _>>(),
        })
    })
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// SMTP authentication to store. A `None` secret keeps the stored one when
/// the method has not changed.
#[derive(Debug, Clone)]
pub enum EmailAuthenticationInput {
    None,
    Password {
        username: String,
        password: Option<String>,
    },
    Xoauth2 {
        username: String,
        token_endpoint: String,
        client_id: String,
        client_secret: Option<String>,
        grant: Xoauth2Grant,
        refresh_token: Option<String>,
        scope: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct UpdateEmailDeliveryCommand {
    pub enabled: bool,
    pub host: String,
    pub port: i64,
    pub security: SmtpSecurity,
    pub sender_address: String,
    pub sender_name: Option<String>,
    pub authentication: EmailAuthenticationInput,
    pub expected_version: Uuid,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateEmailTemplateCommand {
    pub kind: EmailTemplateKind,
    /// The operator's template, or `None` to use the built-in one again.
    pub template: Option<EmailTemplateDraft>,
    pub expected_version: Uuid,
    pub client_mutation_id: Option<String>,
}

/// An operator template as submitted: translations in the order entered.
#[derive(Debug, Clone)]
pub struct EmailTemplateDraft {
    pub default: EmailTemplateContent,
    pub translations: Vec<(String, EmailTemplateContent)>,
}

#[derive(Debug, Clone)]
pub struct SendTestEmailCommand {
    pub recipient: String,
    pub locale: String,
}

fn invalid(code: InstanceErrorCode, field: &str) -> AppError {
    AppError::from_code(code).with_field(field.to_owned())
}

fn trimmed(value: &str) -> String {
    value.trim().to_owned()
}

fn optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn check_length(value: &str, max: usize, field: &str) -> Result<(), AppError> {
    if value.chars().count() > max {
        return Err(AppError::from_code(InstanceErrorCode::EmailTemplateTooLong)
            .with_param("max", max.to_string())
            .with_field(field.to_owned()));
    }
    Ok(())
}

fn required(value: &str, field: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(invalid(InstanceErrorCode::EmailSettingRequired, field));
    }
    check_length(value, MAX_FIELD_LENGTH, field)
}

fn check_token_endpoint(value: &str) -> Result<(), AppError> {
    let field = "authentication.tokenEndpoint";
    required(value, field)?;
    let url = Url::parse(value)
        .map_err(|_| invalid(InstanceErrorCode::InvalidEmailTokenEndpoint, field))?;
    // Plain HTTP only reaches a token endpoint on this machine.
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(invalid(InstanceErrorCode::InvalidEmailTokenEndpoint, field));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid(InstanceErrorCode::InvalidEmailTokenEndpoint, field));
    }
    Ok(())
}

/// The authentication with each newly entered secret already protected.
enum PreparedAuthentication {
    None,
    Password {
        username: String,
        password: Option<ProtectedSecret>,
    },
    Xoauth2 {
        settings: Xoauth2Settings,
        client_secret: Option<ProtectedSecret>,
        refresh_token: Option<ProtectedSecret>,
    },
}

impl PreparedAuthentication {
    /// Combine with the stored authentication: secrets left out keep their
    /// stored value while the method stays the same.
    fn resolve(self, stored: &SmtpAuthentication) -> Result<SmtpAuthentication, AppError> {
        match self {
            Self::None => Ok(SmtpAuthentication::None),
            Self::Password { username, password } => {
                let password = match (password, stored) {
                    (Some(password), _) => password,
                    (None, SmtpAuthentication::Password { password, .. }) => password.clone(),
                    (None, _) => {
                        return Err(invalid(
                            InstanceErrorCode::EmailSettingRequired,
                            "authentication.password",
                        ));
                    }
                };
                Ok(SmtpAuthentication::Password { username, password })
            }
            Self::Xoauth2 {
                mut settings,
                client_secret,
                refresh_token,
            } => {
                let stored = match stored {
                    SmtpAuthentication::Xoauth2(stored) => Some(stored),
                    _ => None,
                };
                settings.client_secret = client_secret
                    .or_else(|| stored.and_then(|stored| stored.client_secret.clone()));
                settings.refresh_token = match settings.grant {
                    Xoauth2Grant::ClientCredentials => None,
                    Xoauth2Grant::RefreshToken => Some(
                        refresh_token
                            .or_else(|| stored.and_then(|stored| stored.refresh_token.clone()))
                            .ok_or_else(|| {
                                invalid(
                                    InstanceErrorCode::EmailSettingRequired,
                                    "authentication.refreshToken",
                                )
                            })?,
                    ),
                };
                Ok(SmtpAuthentication::Xoauth2(settings))
            }
        }
    }
}

impl InstanceSettingService {
    fn email_dependencies(&self) -> Result<&EmailManagementDependencies, AppError> {
        self.email
            .as_ref()
            .ok_or_else(|| AppError::from_code(InstanceErrorCode::EmailDeliveryNotConfigured))
    }

    async fn protect_secret(
        &self,
        secret: Option<String>,
        field: &str,
    ) -> Result<Option<ProtectedSecret>, AppError> {
        let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
            return Ok(None);
        };
        if secret.len() > MAX_SECRET_LENGTH {
            return Err(AppError::from_code(InstanceErrorCode::EmailTemplateTooLong)
                .with_param("max", MAX_SECRET_LENGTH.to_string())
                .with_field(field.to_owned()));
        }
        let token = self
            .email_dependencies()?
            .protector
            .protect(EMAIL_DELIVERY_SECRET_PURPOSE, secret.as_bytes())
            .await
            .map_err(AppError::from)?;
        Ok(Some(ProtectedSecret::from_protected(token)))
    }

    async fn prepare_authentication(
        &self,
        input: EmailAuthenticationInput,
    ) -> Result<PreparedAuthentication, AppError> {
        Ok(match input {
            EmailAuthenticationInput::None => PreparedAuthentication::None,
            EmailAuthenticationInput::Password { username, password } => {
                let username = trimmed(&username);
                required(&username, "authentication.username")?;
                PreparedAuthentication::Password {
                    username,
                    password: self
                        .protect_secret(password, "authentication.password")
                        .await?,
                }
            }
            EmailAuthenticationInput::Xoauth2 {
                username,
                token_endpoint,
                client_id,
                client_secret,
                grant,
                refresh_token,
                scope,
            } => {
                let username = trimmed(&username);
                required(&username, "authentication.username")?;
                let token_endpoint = trimmed(&token_endpoint);
                check_token_endpoint(&token_endpoint)?;
                let client_id = trimmed(&client_id);
                required(&client_id, "authentication.clientId")?;
                let scope = optional(scope);
                if let Some(scope) = &scope {
                    check_length(scope, MAX_FIELD_LENGTH, "authentication.scope")?;
                }
                PreparedAuthentication::Xoauth2 {
                    settings: Xoauth2Settings {
                        username,
                        token_endpoint,
                        client_id,
                        client_secret: None,
                        grant,
                        refresh_token: None,
                        scope,
                    },
                    client_secret: self
                        .protect_secret(client_secret, "authentication.clientSecret")
                        .await?,
                    refresh_token: match grant {
                        Xoauth2Grant::RefreshToken => {
                            self.protect_secret(refresh_token, "authentication.refreshToken")
                                .await?
                        }
                        Xoauth2Grant::ClientCredentials => None,
                    },
                }
            }
        })
    }

    #[tracing::instrument(skip_all, name = "setting.email.update")]
    pub async fn update_email_delivery(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateEmailDeliveryCommand,
    ) -> Result<InstanceSettingsView, AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            self.email_dependencies()?;
            SMTP_PORT_RANGE.check(command.port, "port")?;
            let host = trimmed(&command.host);
            let sender_address = trimmed(&command.sender_address);
            let sender_name = optional(command.sender_name);
            if command.enabled || !host.is_empty() {
                required(&host, "host")?;
            }
            if host.chars().count() > MAX_HOST_LENGTH || host.contains(char::is_whitespace) {
                return Err(invalid(InstanceErrorCode::InvalidEmailAddress, "host"));
            }
            if command.enabled || !sender_address.is_empty() {
                required(&sender_address, "senderAddress")?;
                if !sender_address.validate_email() {
                    return Err(invalid(
                        InstanceErrorCode::InvalidEmailAddress,
                        "senderAddress",
                    ));
                }
            }
            if let Some(name) = &sender_name {
                check_length(name, 255, "senderName")?;
            }
            let authentication = self.prepare_authentication(command.authentication).await?;
            let port = u16::try_from(command.port).unwrap_or(587);
            let build = move |state: &InstanceSettingsState| {
                let next = EmailDeliverySettings {
                    enabled: command.enabled,
                    host,
                    port,
                    security: command.security,
                    sender_address,
                    sender_name,
                    authentication: authentication.resolve(&state.email_delivery.authentication)?,
                };
                Ok(SettingChanges::default().set_section(&next)?)
            };
            self.write(
                authority,
                InstanceSettingSection::Email,
                command.expected_version,
                Box::new(build),
            )
            .await
        }
        .await;
        self.emit(InstanceSettingSection::Email, &result);
        result
    }

    #[tracing::instrument(skip_all, name = "setting.email_template.update", fields(email.template = command.kind.as_str()))]
    pub async fn update_email_template(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateEmailTemplateCommand,
    ) -> Result<InstanceSettingsView, AppError> {
        let section = InstanceSettingSection::EmailTemplate(command.kind);
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let renderer = Arc::clone(&self.email_dependencies()?.renderer);
            let template = command
                .template
                .map(|draft| check_draft(renderer.as_ref(), command.kind, draft))
                .transpose()?;
            let kind = command.kind;
            let build = move |state: &InstanceSettingsState| {
                let mut templates = state.email_templates.clone();
                match template {
                    Some(template) => templates.insert(kind, template),
                    None => templates.remove(&kind),
                };
                Ok(SettingChanges::default().set::<EmailTemplatesSetting>(&templates)?)
            };
            self.write(
                authority,
                section,
                command.expected_version,
                Box::new(build),
            )
            .await
        }
        .await;
        self.emit(section, &result);
        result
    }

    /// Render one language of a draft template with sample values, without
    /// saving it. `locale` is the language previewed; `None` previews the
    /// default content.
    #[tracing::instrument(skip_all, name = "setting.email_template.preview", fields(email.template = kind.as_str()))]
    pub fn preview_email_template(
        &self,
        kind: EmailTemplateKind,
        locale: Option<&str>,
        content: &EmailTemplateContent,
    ) -> Result<RenderedEmail, AppError> {
        let locale = match locale {
            Some(locale) => Some(canonical_locale(locale, "locale")?),
            None => None,
        };
        let renderer = &self.email_dependencies()?.renderer;
        check_template(renderer.as_ref(), kind, locale.as_deref(), content)
            .map_err(|check| check.into_error("content."))
    }

    /// Send a short message with the stored delivery settings.
    #[tracing::instrument(skip_all, name = "setting.email.test")]
    pub async fn send_test_email(&self, command: SendTestEmailCommand) -> Result<(), AppError> {
        let result = async {
            let dependencies = self.email_dependencies()?;
            let recipient = trimmed(&command.recipient);
            if !recipient.validate_email() {
                return Err(invalid(InstanceErrorCode::InvalidEmailAddress, "recipient"));
            }
            let state = self.repository.load().await.map_err(map_repository_error)?;
            if !state.email_delivery.is_configured() {
                return Err(AppError::from_code(
                    InstanceErrorCode::EmailDeliveryNotConfigured,
                ));
            }
            let locale = if command.locale.trim().starts_with("zh") {
                "zh-CN"
            } else {
                "en-US"
            };
            dependencies
                .sender
                .send(&state.email_delivery, test_message(recipient, locale))
                .await
                .map_err(|error| {
                    AppError::from_code(InstanceErrorCode::TestEmailFailed)
                        .with_param(
                            "detail",
                            error.detail().unwrap_or(error.reason()).to_owned(),
                        )
                        .with_source(error)
                })
        }
        .await;
        let mut event = BusinessEvent::business("setting.email.test");
        event = match &result {
            Ok(()) => event.outcome("success"),
            Err(error) => event
                .outcome("failure")
                .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
        };
        self.events.emit(event);
        result
    }
}

/// Why a template cannot be saved, tied to the part it concerns.
struct TemplateCheck {
    error: AppError,
    part: &'static str,
}

impl TemplateCheck {
    fn into_error(self, prefix: &str) -> AppError {
        self.error.with_field(format!("{prefix}{}", self.part))
    }
}

fn canonical_locale(locale: &str, field: &str) -> Result<String, AppError> {
    identity_domain::rbac::metadata::canonicalize_locale(locale).map_err(|_| {
        AppError::from_code(InstanceErrorCode::UnsupportedEmailLocale)
            .with_param("locale", locale.to_owned())
            .with_field(field.to_owned())
    })
}

/// Validate every language of a draft and key its translations by canonical
/// language tag. Field paths follow the input: `default.subject`,
/// `translations.<index>.content.html`.
fn check_draft(
    renderer: &dyn EmailTemplateRenderer,
    kind: EmailTemplateKind,
    draft: EmailTemplateDraft,
) -> Result<EmailTemplate, AppError> {
    check_template(renderer, kind, None, &draft.default)
        .map_err(|check| check.into_error("default."))?;
    if draft.translations.len() > MAX_TEMPLATE_TRANSLATIONS {
        return Err(AppError::from_code(InstanceErrorCode::EmailTemplateTooLong)
            .with_param("max", MAX_TEMPLATE_TRANSLATIONS.to_string())
            .with_field("translations"));
    }
    let mut translations = BTreeMap::new();
    for (index, (locale, content)) in draft.translations.into_iter().enumerate() {
        let locale = canonical_locale(&locale, &format!("translations.{index}.locale"))?;
        check_template(renderer, kind, Some(&locale), &content)
            .map_err(|check| check.into_error(&format!("translations.{index}.content.")))?;
        if translations.insert(locale.clone(), content).is_some() {
            return Err(AppError::from_code(InstanceErrorCode::DuplicateEmailLocale)
                .with_param("locale", locale)
                .with_field(format!("translations.{index}.locale")));
        }
    }
    Ok(EmailTemplate {
        default: draft.default,
        translations,
    })
}

fn check_template(
    renderer: &dyn EmailTemplateRenderer,
    kind: EmailTemplateKind,
    locale: Option<&str>,
    content: &EmailTemplateContent,
) -> Result<RenderedEmail, TemplateCheck> {
    for (value, max, part) in [
        (&content.subject, MAX_SUBJECT_LENGTH, "subject"),
        (&content.html, MAX_BODY_LENGTH, "html"),
    ] {
        if value.chars().count() > max {
            return Err(TemplateCheck {
                error: AppError::from_code(InstanceErrorCode::EmailTemplateTooLong)
                    .with_param("max", max.to_string()),
                part,
            });
        }
        if value.trim().is_empty() {
            return Err(TemplateCheck {
                error: AppError::from_code(InstanceErrorCode::EmailSettingRequired),
                part,
            });
        }
    }
    renderer
        .render(content, &kind.sample_context(locale.unwrap_or("en")))
        .map_err(|EmailTemplateRenderError { part, detail }| TemplateCheck {
            error: AppError::from_code(InstanceErrorCode::InvalidEmailTemplate)
                .with_param("detail", detail),
            part: part.as_str(),
        })
}

fn test_message(recipient: String, locale: &str) -> EmailMessage {
    let (subject, line) = if locale == "zh-CN" {
        ("测试邮件", "这是一封测试邮件，说明邮件发送设置可以正常使用")
    } else {
        (
            "Test email",
            "This is a test email. Your email delivery settings work.",
        )
    };
    EmailMessage {
        to_address: recipient,
        to_name: None,
        subject: subject.to_owned(),
        html: format!("<!doctype html><html lang=\"{locale}\"><body><p>{line}</p></body></html>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(token: &str) -> ProtectedSecret {
        ProtectedSecret::from_protected(token.to_owned())
    }

    fn stored_oauth() -> SmtpAuthentication {
        SmtpAuthentication::Xoauth2(Xoauth2Settings {
            username: "mailer@example.com".to_owned(),
            token_endpoint: "https://login.example.com/token".to_owned(),
            client_id: "client".to_owned(),
            client_secret: Some(secret("stored-secret")),
            grant: Xoauth2Grant::RefreshToken,
            refresh_token: Some(secret("stored-refresh")),
            scope: None,
        })
    }

    fn oauth_input(grant: Xoauth2Grant) -> PreparedAuthentication {
        PreparedAuthentication::Xoauth2 {
            settings: Xoauth2Settings {
                username: "mailer@example.com".to_owned(),
                token_endpoint: "https://login.example.com/token".to_owned(),
                client_id: "client".to_owned(),
                client_secret: None,
                grant,
                refresh_token: None,
                scope: None,
            },
            client_secret: None,
            refresh_token: None,
        }
    }

    #[test]
    fn omitted_secrets_keep_the_stored_ones_only_for_the_same_method() {
        let SmtpAuthentication::Xoauth2(kept) = oauth_input(Xoauth2Grant::RefreshToken)
            .resolve(&stored_oauth())
            .unwrap()
        else {
            panic!("expected XOAUTH2");
        };
        assert_eq!(kept.client_secret, Some(secret("stored-secret")));
        assert_eq!(kept.refresh_token, Some(secret("stored-refresh")));

        let switched = PreparedAuthentication::Password {
            username: "mailer".to_owned(),
            password: None,
        }
        .resolve(&stored_oauth())
        .unwrap_err();
        assert_eq!(
            switched.code(),
            InstanceErrorCode::EmailSettingRequired as u32
        );

        let missing_refresh = oauth_input(Xoauth2Grant::RefreshToken)
            .resolve(&SmtpAuthentication::None)
            .unwrap_err();
        assert_eq!(
            missing_refresh.code(),
            InstanceErrorCode::EmailSettingRequired as u32
        );
    }

    #[test]
    fn client_credentials_drops_a_stored_refresh_token() {
        let SmtpAuthentication::Xoauth2(next) = oauth_input(Xoauth2Grant::ClientCredentials)
            .resolve(&stored_oauth())
            .unwrap()
        else {
            panic!("expected XOAUTH2");
        };
        assert_eq!(next.refresh_token, None);
        assert_eq!(next.client_secret, Some(secret("stored-secret")));
    }

    #[test]
    fn audited_delivery_values_fingerprint_secrets() {
        let settings = EmailDeliverySettings {
            authentication: SmtpAuthentication::Password {
                username: "mailer".to_owned(),
                password: secret("protected-token"),
            },
            ..EmailDeliverySettings::default()
        };
        let audited = email_delivery_audit_values(&settings).to_string();
        assert!(!audited.contains("protected-token"));
        assert!(audited.contains("protected:"));
        assert!(audited.contains("mailer"));
    }

    #[test]
    fn token_endpoints_must_use_https_off_this_machine() {
        assert!(check_token_endpoint("https://oauth2.example.com/token").is_ok());
        assert!(check_token_endpoint("http://localhost:8080/token").is_ok());
        assert!(check_token_endpoint("http://oauth2.example.com/token").is_err());
        assert!(check_token_endpoint("https://user:pass@example.com/token").is_err());
        assert!(check_token_endpoint("token").is_err());
    }

    struct EchoRenderer;

    impl EmailTemplateRenderer for EchoRenderer {
        fn render(
            &self,
            content: &EmailTemplateContent,
            _context: &Value,
        ) -> Result<RenderedEmail, EmailTemplateRenderError> {
            if content.html.contains("{% broken") {
                return Err(EmailTemplateRenderError {
                    part: crate::email::EmailTemplatePart::Html,
                    detail: "unexpected tag".to_owned(),
                });
            }
            Ok(RenderedEmail {
                subject: content.subject.clone(),
                html: content.html.clone(),
            })
        }
    }

    fn page(html: &str) -> EmailTemplateContent {
        EmailTemplateContent {
            subject: "Subject".to_owned(),
            html: html.to_owned(),
        }
    }

    fn field(error: &AppError) -> String {
        error
            .validation()
            .and_then(|validation| validation.fields().first())
            .map(|field| field.field().to_owned())
            .unwrap_or_default()
    }

    #[test]
    fn a_draft_keys_translations_by_canonical_language_tag() {
        let kind = EmailTemplateKind::SignInCode;
        let template = check_draft(
            &EchoRenderer,
            kind,
            EmailTemplateDraft {
                default: page("<p>hi</p>"),
                translations: vec![("zh_cn".to_owned(), page("<p>你好</p>"))],
            },
        )
        .unwrap();
        assert_eq!(template.translations.keys().collect::<Vec<_>>(), ["zh-CN"]);

        let duplicate = check_draft(
            &EchoRenderer,
            kind,
            EmailTemplateDraft {
                default: page("<p>hi</p>"),
                translations: vec![
                    ("zh-CN".to_owned(), page("<p>1</p>")),
                    ("zh_cn".to_owned(), page("<p>2</p>")),
                ],
            },
        )
        .unwrap_err();
        assert_eq!(
            duplicate.code(),
            InstanceErrorCode::DuplicateEmailLocale as u32
        );
        assert_eq!(field(&duplicate), "translations.1.locale");
    }

    #[test]
    fn a_draft_error_names_the_language_and_part() {
        let kind = EmailTemplateKind::SignInCode;
        let broken = check_draft(
            &EchoRenderer,
            kind,
            EmailTemplateDraft {
                default: page("<p>hi</p>"),
                translations: vec![("fr".to_owned(), page("{% broken %}"))],
            },
        )
        .unwrap_err();
        assert_eq!(
            broken.code(),
            InstanceErrorCode::InvalidEmailTemplate as u32
        );
        assert_eq!(field(&broken), "translations.0.content.html");

        let empty = check_draft(
            &EchoRenderer,
            kind,
            EmailTemplateDraft {
                default: page("  "),
                translations: Vec::new(),
            },
        )
        .unwrap_err();
        assert_eq!(field(&empty), "default.html");
    }
}
