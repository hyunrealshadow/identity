//! GraphQL types of email delivery and email template settings. Secrets are
//! write-only: a read says whether one is stored, never what it is.

use async_graphql::{Enum, InputObject, Object, SimpleObject};
use identity_application::{
    email::{
        EmailTemplate as AppEmailTemplate, EmailTemplateContent as AppEmailTemplateContent,
        EmailTemplateKind as AppEmailTemplateKind,
        EmailTemplatePreviewScenario as AppEmailTemplatePreviewScenario, RenderedEmail,
    },
    setting::{
        SmtpSecurity as AppSmtpSecurity, Xoauth2Grant as AppXoauth2Grant,
        email::{
            EMAIL_LOGIN_MAX_SENDS_RANGE, EMAIL_PASSWORD_RESET_LIFETIME_MINUTES_RANGE,
            EMAIL_REGISTRATION_LIFETIME_MINUTES_RANGE, EMAIL_RESEND_INTERVAL_SECONDS_RANGE,
            EMAIL_SIGN_IN_CODE_LIFETIME_MINUTES_RANGE, EMAIL_USER_INVITATION_LIFETIME_DAYS_RANGE,
            EMAIL_VERIFICATION_LIFETIME_HOURS_RANGE, EMAIL_VERIFICATION_MAX_SENDS_RANGE,
            EMAIL_VERIFICATION_SEND_WINDOW_HOURS_RANGE,
            EmailAuthenticationInput as AppEmailAuthenticationInput,
            EmailAuthenticationMethod as AppEmailAuthenticationMethod, EmailAuthenticationView,
            EmailDeliveryView, EmailPolicyView, EmailSettingsView, EmailTemplateDraft,
            EmailTemplateView, SMTP_PORT_RANGE,
        },
    },
};
use uuid::Uuid;

use super::types::IntRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum SmtpSecurity {
    /// TLS from the first byte, usually on port 465.
    Tls,
    /// A plain connection that must upgrade with STARTTLS, usually on port 587.
    StartTls,
    /// No transport security; only for a relay on a trusted network.
    None,
}

impl From<AppSmtpSecurity> for SmtpSecurity {
    fn from(value: AppSmtpSecurity) -> Self {
        match value {
            AppSmtpSecurity::Tls => Self::Tls,
            AppSmtpSecurity::StartTls => Self::StartTls,
            AppSmtpSecurity::None => Self::None,
        }
    }
}

impl From<SmtpSecurity> for AppSmtpSecurity {
    fn from(value: SmtpSecurity) -> Self {
        match value {
            SmtpSecurity::Tls => Self::Tls,
            SmtpSecurity::StartTls => Self::StartTls,
            SmtpSecurity::None => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum EmailAuthenticationMethod {
    /// An unauthenticated relay.
    None,
    /// A username and password.
    Password,
    /// An OAuth 2.0 access token (`AUTH XOAUTH2`).
    #[graphql(name = "XOAUTH2")]
    Xoauth2,
}

impl From<AppEmailAuthenticationMethod> for EmailAuthenticationMethod {
    fn from(value: AppEmailAuthenticationMethod) -> Self {
        match value {
            AppEmailAuthenticationMethod::None => Self::None,
            AppEmailAuthenticationMethod::Password => Self::Password,
            AppEmailAuthenticationMethod::Xoauth2 => Self::Xoauth2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum Xoauth2Grant {
    /// Exchange a refresh token issued to the mailbox user.
    RefreshToken,
    /// Authenticate as the OAuth client itself.
    ClientCredentials,
}

impl From<AppXoauth2Grant> for Xoauth2Grant {
    fn from(value: AppXoauth2Grant) -> Self {
        match value {
            AppXoauth2Grant::RefreshToken => Self::RefreshToken,
            AppXoauth2Grant::ClientCredentials => Self::ClientCredentials,
        }
    }
}

impl From<Xoauth2Grant> for AppXoauth2Grant {
    fn from(value: Xoauth2Grant) -> Self {
        match value {
            Xoauth2Grant::RefreshToken => Self::RefreshToken,
            Xoauth2Grant::ClientCredentials => Self::ClientCredentials,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum EmailTemplateKind {
    /// The one-time code and sign-in link of email sign-in.
    SignInCode,
    /// The link that verifies an account's email address.
    EmailVerification,
    /// The link that replaces a forgotten password from the sign-in flow.
    PasswordReset,
    /// The link with which an invited user sets their first password.
    UserInvitation,
    /// The link that continues creating an account from the sign-in flow.
    Registration,
}

impl From<AppEmailTemplateKind> for EmailTemplateKind {
    fn from(value: AppEmailTemplateKind) -> Self {
        match value {
            AppEmailTemplateKind::SignInCode => Self::SignInCode,
            AppEmailTemplateKind::EmailVerification => Self::EmailVerification,
            AppEmailTemplateKind::PasswordReset => Self::PasswordReset,
            AppEmailTemplateKind::UserInvitation => Self::UserInvitation,
            AppEmailTemplateKind::Registration => Self::Registration,
        }
    }
}

impl From<EmailTemplateKind> for AppEmailTemplateKind {
    fn from(value: EmailTemplateKind) -> Self {
        match value {
            EmailTemplateKind::SignInCode => Self::SignInCode,
            EmailTemplateKind::EmailVerification => Self::EmailVerification,
            EmailTemplateKind::PasswordReset => Self::PasswordReset,
            EmailTemplateKind::UserInvitation => Self::UserInvitation,
            EmailTemplateKind::Registration => Self::Registration,
        }
    }
}

/// Conditional sample scenario rendered when previewing or test-sending an
/// email template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(crate) enum EmailTemplatePreviewScenario {
    /// Sign-in code requested through an OAuth/OIDC client application.
    SignInCodeWithApplication,
    /// Sign-in code requested directly without an application name.
    SignInCodeWithoutApplication,
    /// Verifying a new email address before replacing the current one.
    EmailVerificationChangeAddress,
    /// Verifying the account's current email address.
    EmailVerificationCurrentAddress,
    /// Registration link when the email address is not yet registered.
    RegistrationNewAccount,
    /// Existing-account notice when the email address already has an account.
    RegistrationExistingAccount,
}

impl From<AppEmailTemplatePreviewScenario> for EmailTemplatePreviewScenario {
    fn from(value: AppEmailTemplatePreviewScenario) -> Self {
        match value {
            AppEmailTemplatePreviewScenario::SignInCodeWithApplication => {
                Self::SignInCodeWithApplication
            }
            AppEmailTemplatePreviewScenario::SignInCodeWithoutApplication => {
                Self::SignInCodeWithoutApplication
            }
            AppEmailTemplatePreviewScenario::EmailVerificationChangeAddress => {
                Self::EmailVerificationChangeAddress
            }
            AppEmailTemplatePreviewScenario::EmailVerificationCurrentAddress => {
                Self::EmailVerificationCurrentAddress
            }
            AppEmailTemplatePreviewScenario::RegistrationNewAccount => Self::RegistrationNewAccount,
            AppEmailTemplatePreviewScenario::RegistrationExistingAccount => {
                Self::RegistrationExistingAccount
            }
        }
    }
}

impl From<EmailTemplatePreviewScenario> for AppEmailTemplatePreviewScenario {
    fn from(value: EmailTemplatePreviewScenario) -> Self {
        match value {
            EmailTemplatePreviewScenario::SignInCodeWithApplication => {
                Self::SignInCodeWithApplication
            }
            EmailTemplatePreviewScenario::SignInCodeWithoutApplication => {
                Self::SignInCodeWithoutApplication
            }
            EmailTemplatePreviewScenario::EmailVerificationChangeAddress => {
                Self::EmailVerificationChangeAddress
            }
            EmailTemplatePreviewScenario::EmailVerificationCurrentAddress => {
                Self::EmailVerificationCurrentAddress
            }
            EmailTemplatePreviewScenario::RegistrationNewAccount => Self::RegistrationNewAccount,
            EmailTemplatePreviewScenario::RegistrationExistingAccount => {
                Self::RegistrationExistingAccount
            }
        }
    }
}

pub(crate) struct EmailSettings {
    view: EmailSettingsView,
}

impl From<&EmailSettingsView> for EmailSettings {
    fn from(view: &EmailSettingsView) -> Self {
        Self { view: view.clone() }
    }
}

#[Object]
impl EmailSettings {
    /// The SMTP server email is sent through.
    async fn delivery(&self) -> EmailDeliverySettings {
        EmailDeliverySettings {
            view: self.view.delivery.clone(),
        }
    }

    /// Lifetimes, resend cadence, and send limits for outbound system emails.
    async fn policy(&self) -> EmailPolicySettings {
        EmailPolicySettings {
            view: self.view.policy.clone(),
        }
    }

    /// Every kind of email, with its template in each supported locale.
    async fn templates(&self) -> Vec<EmailTemplate> {
        self.view
            .templates
            .iter()
            .cloned()
            .map(|view| EmailTemplate { view })
            .collect()
    }
}

pub(crate) struct EmailDeliverySettings {
    view: EmailDeliveryView,
}

#[Object]
impl EmailDeliverySettings {
    async fn enabled(&self) -> bool {
        self.view.enabled
    }

    async fn host(&self) -> &str {
        &self.view.host
    }

    async fn port(&self) -> i32 {
        i32::from(self.view.port)
    }

    async fn port_range(&self) -> IntRange {
        SMTP_PORT_RANGE.into()
    }

    async fn security(&self) -> SmtpSecurity {
        self.view.security.into()
    }

    /// The `From` address of every message.
    async fn sender_address(&self) -> &str {
        &self.view.sender_address
    }

    async fn sender_name(&self) -> Option<&str> {
        self.view.sender_name.as_deref()
    }

    async fn authentication(&self) -> EmailAuthentication {
        EmailAuthentication::from(&self.view.authentication)
    }

    /// Enabled with a server and a sender address, so email can be sent.
    async fn configured(&self) -> bool {
        self.view.configured
    }

    /// UUID optimistic-lock version of this section.
    async fn version(&self) -> Uuid {
        self.view.version
    }
}

pub(crate) struct EmailPolicySettings {
    view: EmailPolicyView,
}

#[Object]
impl EmailPolicySettings {
    async fn sign_in_code_lifetime_minutes(&self) -> u32 {
        self.view.sign_in_code_lifetime_minutes
    }

    async fn sign_in_code_lifetime_minutes_range(&self) -> IntRange {
        EMAIL_SIGN_IN_CODE_LIFETIME_MINUTES_RANGE.into()
    }

    async fn password_reset_lifetime_minutes(&self) -> u32 {
        self.view.password_reset_lifetime_minutes
    }

    async fn password_reset_lifetime_minutes_range(&self) -> IntRange {
        EMAIL_PASSWORD_RESET_LIFETIME_MINUTES_RANGE.into()
    }

    async fn registration_lifetime_minutes(&self) -> u32 {
        self.view.registration_lifetime_minutes
    }

    async fn registration_lifetime_minutes_range(&self) -> IntRange {
        EMAIL_REGISTRATION_LIFETIME_MINUTES_RANGE.into()
    }

    async fn email_verification_lifetime_hours(&self) -> u32 {
        self.view.email_verification_lifetime_hours
    }

    async fn email_verification_lifetime_hours_range(&self) -> IntRange {
        EMAIL_VERIFICATION_LIFETIME_HOURS_RANGE.into()
    }

    async fn user_invitation_lifetime_days(&self) -> u32 {
        self.view.user_invitation_lifetime_days
    }

    async fn user_invitation_lifetime_days_range(&self) -> IntRange {
        EMAIL_USER_INVITATION_LIFETIME_DAYS_RANGE.into()
    }

    async fn resend_interval_seconds(&self) -> u32 {
        self.view.resend_interval_seconds
    }

    async fn resend_interval_seconds_range(&self) -> IntRange {
        EMAIL_RESEND_INTERVAL_SECONDS_RANGE.into()
    }

    async fn login_max_sends(&self) -> u32 {
        self.view.login_max_sends
    }

    async fn login_max_sends_range(&self) -> IntRange {
        EMAIL_LOGIN_MAX_SENDS_RANGE.into()
    }

    async fn verification_max_sends(&self) -> u32 {
        self.view.verification_max_sends
    }

    async fn verification_max_sends_range(&self) -> IntRange {
        EMAIL_VERIFICATION_MAX_SENDS_RANGE.into()
    }

    async fn verification_send_window_hours(&self) -> u32 {
        self.view.verification_send_window_hours
    }

    async fn verification_send_window_hours_range(&self) -> IntRange {
        EMAIL_VERIFICATION_SEND_WINDOW_HOURS_RANGE.into()
    }

    /// UUID optimistic-lock version of this section.
    async fn version(&self) -> Uuid {
        self.view.version
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateEmailPolicySettingsInput {
    pub sign_in_code_lifetime_minutes: u32,
    pub password_reset_lifetime_minutes: u32,
    pub registration_lifetime_minutes: u32,
    pub email_verification_lifetime_hours: u32,
    pub user_invitation_lifetime_days: u32,
    pub resend_interval_seconds: u32,
    pub login_max_sends: u32,
    pub verification_max_sends: u32,
    pub verification_send_window_hours: u32,
    pub expected_version: Uuid,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

/// SMTP authentication. Secrets are reported only as stored or not.
#[derive(SimpleObject)]
pub(crate) struct EmailAuthentication {
    method: EmailAuthenticationMethod,
    username: Option<String>,
    password_set: bool,
    token_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret_set: bool,
    grant: Option<Xoauth2Grant>,
    refresh_token_set: bool,
    scope: Option<String>,
}

impl From<&EmailAuthenticationView> for EmailAuthentication {
    fn from(view: &EmailAuthenticationView) -> Self {
        Self {
            method: view.method.into(),
            username: view.username.clone(),
            password_set: view.password_set,
            token_endpoint: view.token_endpoint.clone(),
            client_id: view.client_id.clone(),
            client_secret_set: view.client_secret_set,
            grant: view.grant.map(Into::into),
            refresh_token_set: view.refresh_token_set,
            scope: view.scope.clone(),
        }
    }
}

pub(crate) struct EmailTemplate {
    view: EmailTemplateView,
}

#[Object]
impl EmailTemplate {
    async fn kind(&self) -> EmailTemplateKind {
        self.view.kind.into()
    }

    /// Variables the template receives, as dotted paths.
    async fn variables(&self) -> Vec<&'static str> {
        self.view.variables.to_vec()
    }

    /// Sample scenarios available when previewing or test-sending this template.
    async fn preview_scenarios(&self) -> Vec<EmailTemplatePreviewScenario> {
        self.view
            .preview_scenarios
            .iter()
            .copied()
            .map(Into::into)
            .collect()
    }

    /// Whether an operator replaced the built-in template.
    async fn customized(&self) -> bool {
        self.view.customized
    }

    /// The template that is sent.
    async fn content(&self) -> LocalizedEmailTemplate {
        LocalizedEmailTemplate::from(&self.view.template)
    }

    /// The template shipped with the instance, used while not customized.
    async fn built_in(&self) -> LocalizedEmailTemplate {
        LocalizedEmailTemplate::from(&self.view.built_in)
    }

    /// UUID optimistic-lock version of this template.
    async fn version(&self) -> Uuid {
        self.view.version
    }
}

/// Default content, used when no translation fits the reader, and its
/// translations.
#[derive(SimpleObject)]
pub(crate) struct LocalizedEmailTemplate {
    default: EmailTemplateContent,
    /// Ordered by language tag.
    translations: Vec<EmailTemplateTranslation>,
}

impl From<&AppEmailTemplate> for LocalizedEmailTemplate {
    fn from(template: &AppEmailTemplate) -> Self {
        Self {
            default: EmailTemplateContent::from(&template.default),
            translations: template
                .translations
                .iter()
                .map(|(locale, content)| EmailTemplateTranslation {
                    locale: locale.clone(),
                    content: EmailTemplateContent::from(content),
                })
                .collect(),
        }
    }
}

/// One language of a template, as Tera source.
#[derive(SimpleObject)]
pub(crate) struct EmailTemplateContent {
    subject: String,
    html: String,
}

impl From<&AppEmailTemplateContent> for EmailTemplateContent {
    fn from(content: &AppEmailTemplateContent) -> Self {
        Self {
            subject: content.subject.clone(),
            html: content.html.clone(),
        }
    }
}

#[derive(SimpleObject)]
pub(crate) struct EmailTemplateTranslation {
    /// Language tag.
    locale: String,
    content: EmailTemplateContent,
}

/// SMTP authentication to store. Leave a secret out to keep the stored one
/// while the method stays the same.
#[derive(Clone, InputObject)]
pub(crate) struct EmailAuthenticationInput {
    pub method: EmailAuthenticationMethod,
    #[graphql(validator(chars_max_length = 2048))]
    pub username: Option<String>,
    #[graphql(secret, validator(chars_max_length = 8192))]
    pub password: Option<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub token_endpoint: Option<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub client_id: Option<String>,
    #[graphql(secret, validator(chars_max_length = 8192))]
    pub client_secret: Option<String>,
    pub grant: Option<Xoauth2Grant>,
    #[graphql(secret, validator(chars_max_length = 8192))]
    pub refresh_token: Option<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub scope: Option<String>,
}

impl From<EmailAuthenticationInput> for AppEmailAuthenticationInput {
    fn from(input: EmailAuthenticationInput) -> Self {
        let username = input.username.unwrap_or_default();
        match input.method {
            EmailAuthenticationMethod::None => Self::None,
            EmailAuthenticationMethod::Password => Self::Password {
                username,
                password: input.password,
            },
            EmailAuthenticationMethod::Xoauth2 => Self::Xoauth2 {
                username,
                token_endpoint: input.token_endpoint.unwrap_or_default(),
                client_id: input.client_id.unwrap_or_default(),
                client_secret: input.client_secret,
                grant: input.grant.unwrap_or(Xoauth2Grant::RefreshToken).into(),
                refresh_token: input.refresh_token,
                scope: input.scope,
            },
        }
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateEmailDeliverySettingsInput {
    pub enabled: bool,
    #[graphql(validator(chars_max_length = 253))]
    pub host: String,
    pub port: i32,
    pub security: SmtpSecurity,
    #[graphql(validator(chars_max_length = 320))]
    pub sender_address: String,
    #[graphql(validator(chars_max_length = 255))]
    pub sender_name: Option<String>,
    pub authentication: EmailAuthenticationInput,
    pub expected_version: Uuid,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct EmailTemplateContentInput {
    #[graphql(validator(chars_max_length = 500))]
    pub subject: String,
    #[graphql(validator(chars_max_length = 100000))]
    pub html: String,
}

impl From<EmailTemplateContentInput> for AppEmailTemplateContent {
    fn from(input: EmailTemplateContentInput) -> Self {
        Self {
            subject: input.subject,
            html: input.html,
        }
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct EmailTemplateTranslationInput {
    /// Language tag.
    #[graphql(validator(chars_max_length = 35))]
    pub locale: String,
    pub content: EmailTemplateContentInput,
}

#[derive(Clone, InputObject)]
pub(crate) struct LocalizedEmailTemplateInput {
    pub default: EmailTemplateContentInput,
    #[graphql(validator(max_items = 20))]
    pub translations: Vec<EmailTemplateTranslationInput>,
}

impl From<LocalizedEmailTemplateInput> for EmailTemplateDraft {
    fn from(input: LocalizedEmailTemplateInput) -> Self {
        Self {
            default: input.default.into(),
            translations: input
                .translations
                .into_iter()
                .map(|translation| (translation.locale, translation.content.into()))
                .collect(),
        }
    }
}

/// Replace one template with an operator's own, or with `content: null` use
/// the built-in template again.
#[derive(Clone, InputObject)]
pub(crate) struct UpdateEmailTemplateInput {
    pub kind: EmailTemplateKind,
    pub content: Option<LocalizedEmailTemplateInput>,
    pub expected_version: Uuid,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct SendTestEmailInput {
    #[graphql(validator(chars_max_length = 320))]
    pub recipient: String,
    /// Language of the message.
    #[graphql(validator(chars_max_length = 35))]
    pub locale: String,
    /// Template draft to render instead of the generic delivery test message.
    pub template: Option<EmailTemplatePreviewInput>,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(SimpleObject)]
pub(crate) struct SendTestEmailPayload {
    /// The mail server accepted the message.
    pub sent: bool,
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct EmailTemplatePreviewInput {
    pub kind: EmailTemplateKind,
    /// The language previewed; omit it for the default content.
    #[graphql(validator(chars_max_length = 35))]
    pub locale: Option<String>,
    /// Sample scenario to render; omit it for the template's default scenario.
    pub scenario: Option<EmailTemplatePreviewScenario>,
    pub content: EmailTemplateContentInput,
}

/// A template rendered with sample values.
#[derive(SimpleObject)]
pub(crate) struct EmailTemplatePreview {
    pub subject: String,
    pub html: String,
}

impl From<RenderedEmail> for EmailTemplatePreview {
    fn from(rendered: RenderedEmail) -> Self {
        Self {
            subject: rendered.subject,
            html: rendered.html,
        }
    }
}
