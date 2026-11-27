//! Instance settings management: reading and editing the instance-wide
//! settings an operator may change at runtime.
//!
//! Settings are grouped into sections. Each editable section is one write unit
//! with its own optimistic-lock `version`: a UUID derived from the section's
//! stored values, so any successful change replaces it and a stale editor is
//! rejected. Public addresses and installation facts are read-only here; they
//! are deployment configuration, not runtime preferences.
//!
//! The entry guard established the management scope when the request started.
//! The repository re-checks live authority, compares the version and appends
//! the semantic audit record inside the write transaction.

use identity_domain::audit::AuditAction;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::{openid_connect::OAuthProtocolVersion, rbac::builtin::deterministic_oid};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use super::{
    AppSettings, BreachedPasswordCheckEnabledSetting, EmailDeliverySettings, EmailPolicySettings,
    EmailSignInEnabledSetting, IdentifierEnumerationAllowedSetting, InstallationSettings,
    LockoutDurationMinutesSetting, MaxFailedAttemptsSetting, OpenIdConnectSettings,
    PasswordHashSetting, PasswordHistoryCountSetting, PasswordMaxAgeDaysSetting,
    PasswordMinLengthSetting, PasswordResetEnabledSetting, RegistrationEnabledSetting,
    SessionSettings, SettingChanges,
    email::{EmailManagementDependencies, EmailSettingsView},
    runtime::RefreshableSetting,
};
use crate::{
    authentication::password::HashOptions,
    authorization::ManagementAuthorizationError,
    email::{EmailTemplateKind, EmailTemplates},
    error::{
        AppError,
        codes::{authorization, instance},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::RbacManagementAuthority,
    user::model::{Argon2Options, Argon2Variant, Argon2Version},
};

pub use crate::authorization::MAX_CLIENT_MUTATION_ID_LENGTH;

/// Inclusive bounds an operator may choose for one numeric setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingRange {
    pub min: i64,
    pub max: i64,
}

impl SettingRange {
    const fn new(min: i64, max: i64) -> Self {
        Self { min, max }
    }

    pub(crate) fn check(self, value: i64, field: &'static str) -> Result<(), AppError> {
        if (self.min..=self.max).contains(&value) {
            return Ok(());
        }
        Err(instance::error::SettingOutOfRange::new(self.min, self.max).with_field(field))
    }
}

pub const PUSHED_AUTHORIZATION_LIFETIME_RANGE: SettingRange = SettingRange::new(10, 600);
pub const DEVICE_AUTHORIZATION_LIFETIME_RANGE: SettingRange = SettingRange::new(60, 3_600);
pub const DEVICE_POLLING_INTERVAL_RANGE: SettingRange = SettingRange::new(1, 60);
pub const ACCESS_TOKEN_LIFETIME_RANGE: SettingRange = SettingRange::new(60, 86_400);
pub const ID_TOKEN_LIFETIME_RANGE: SettingRange = SettingRange::new(60, 86_400);
pub const REFRESH_TOKEN_LIFETIME_DAYS_RANGE: SettingRange = SettingRange::new(1, 365);
pub const AUTHORIZATION_CODE_LIFETIME_RANGE: SettingRange = SettingRange::new(30, 600);
pub const ARGON2_TIME_COST_RANGE: SettingRange = SettingRange::new(1, 10);
/// KiB. The lower bound follows the commonly recommended Argon2id minimum.
pub const ARGON2_MEMORY_COST_RANGE: SettingRange = SettingRange::new(19_456, 1_048_576);
pub const ARGON2_PARALLELISM_RANGE: SettingRange = SettingRange::new(1, 16);
/// Days; `0` turns password expiry off.
pub const PASSWORD_MAX_AGE_DAYS_RANGE: SettingRange = SettingRange::new(0, 3_650);
/// Recent passwords a new one may not repeat; `0` turns the check off.
pub const PASSWORD_HISTORY_COUNT_RANGE: SettingRange = SettingRange::new(0, 24);
pub const MAX_FAILED_ATTEMPTS_RANGE: SettingRange = SettingRange::new(3, 20);
pub const LOCKOUT_DURATION_MINUTES_RANGE: SettingRange = SettingRange::new(1, 1_440);
pub const PASSWORD_MIN_LENGTH_RANGE: SettingRange = SettingRange::new(8, 128);
pub const SESSION_LIFETIME_HOURS_RANGE: SettingRange = SettingRange::new(1, 2_160);
pub const ELEVATED_AUTHENTICATION_LIFETIME_MINUTES_RANGE: SettingRange =
    SettingRange::new(5, 1_440);
pub const RECENT_AUTHENTICATION_LIFETIME_MINUTES_RANGE: SettingRange = SettingRange::new(1, 60);
pub const LOGIN_LIFETIME_MINUTES_RANGE: SettingRange = SettingRange::new(1, 60);

/// One editable group of instance settings, written and versioned as a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceSettingSection {
    Protocol,
    Authentication,
    Session,
    /// How email is delivered.
    Email,
    /// Lifetimes, resend cadence, and send limits of system emails.
    EmailPolicy,
    /// Every locale of one email template.
    EmailTemplate(EmailTemplateKind),
}

impl InstanceSettingSection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Authentication => "authentication",
            Self::Session => "session",
            Self::Email => "email",
            Self::EmailPolicy => "email_policy",
            Self::EmailTemplate(EmailTemplateKind::SignInCode) => "email_template.sign_in_code",
            Self::EmailTemplate(EmailTemplateKind::EmailVerification) => {
                "email_template.email_verification"
            }
            Self::EmailTemplate(EmailTemplateKind::PasswordReset) => {
                "email_template.password_reset"
            }
            Self::EmailTemplate(EmailTemplateKind::UserInvitation) => {
                "email_template.user_invitation"
            }
            Self::EmailTemplate(EmailTemplateKind::Registration) => "email_template.registration",
        }
    }

    #[must_use]
    pub const fn audit_action(self) -> AuditAction {
        match self {
            Self::Protocol => AuditAction::SettingProtocolUpdate,
            Self::Authentication => AuditAction::SettingAuthenticationUpdate,
            Self::Session => AuditAction::SettingSessionUpdate,
            Self::Email => AuditAction::SettingEmailUpdate,
            Self::EmailPolicy => AuditAction::SettingEmailPolicyUpdate,
            Self::EmailTemplate(_) => AuditAction::SettingEmailTemplateUpdate,
        }
    }

    /// Stable audit target identity of this section.
    #[must_use]
    pub fn audit_target_oid(self) -> Uuid {
        deterministic_oid(&format!("instance-setting-section:{}", self.as_str()))
    }

    /// The optimistic-lock version of this section in `state`.
    #[must_use]
    pub fn version(self, state: &InstanceSettingsState) -> Uuid {
        match self {
            Self::Protocol => content_version(self, &state.openid_connect),
            Self::Authentication => content_version(self, &state.authentication_values()),
            Self::Session => content_version(self, &state.session),
            Self::Email => content_version(self, &state.email_delivery),
            Self::EmailPolicy => content_version(self, &state.email_policy),
            Self::EmailTemplate(kind) => content_version(self, &state.email_templates.get(&kind)),
        }
    }
}

/// A UUID determined by the section's stored values: identical values give the
/// same version, and any change gives another one.
fn content_version<T: Serialize>(section: InstanceSettingSection, value: &T) -> Uuid {
    let encoded = serde_json::to_string(&(section.as_str(), value)).unwrap_or_default();
    deterministic_oid(&format!("instance-setting-version:{encoded}"))
}

/// Every instance setting this surface reads, as stored right now.
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceSettingsState {
    pub app: AppSettings,
    pub installation: InstallationSettings,
    pub openid_connect: OpenIdConnectSettings,
    pub session: SessionSettings,
    pub password_hash: HashOptions,
    pub breached_password_check_enabled: bool,
    pub identifier_enumeration_allowed: bool,
    pub email_sign_in_enabled: bool,
    pub password_reset_enabled: bool,
    pub registration_enabled: bool,
    pub password_max_age_days: u32,
    pub password_history_count: u32,
    pub password_min_length: u32,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub email_delivery: EmailDeliverySettings,
    pub email_policy: EmailPolicySettings,
    pub email_templates: EmailTemplates,
}

/// The stored values of the authentication section, as versioned and audited.
#[derive(Debug, PartialEq, Serialize)]
pub struct AuthenticationSectionValues<'a> {
    pub password_hash: &'a HashOptions,
    pub breached_password_check_enabled: bool,
    pub identifier_enumeration_allowed: bool,
    pub email_sign_in_enabled: bool,
    pub password_reset_enabled: bool,
    pub registration_enabled: bool,
    pub password_max_age_days: u32,
    pub password_history_count: u32,
    pub password_min_length: u32,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
}

impl InstanceSettingsState {
    #[must_use]
    pub fn authentication_values(&self) -> AuthenticationSectionValues<'_> {
        AuthenticationSectionValues {
            password_hash: &self.password_hash,
            breached_password_check_enabled: self.breached_password_check_enabled,
            identifier_enumeration_allowed: self.identifier_enumeration_allowed,
            email_sign_in_enabled: self.email_sign_in_enabled,
            password_reset_enabled: self.password_reset_enabled,
            registration_enabled: self.registration_enabled,
            password_max_age_days: self.password_max_age_days,
            password_history_count: self.password_history_count,
            password_min_length: self.password_min_length,
            max_failed_attempts: self.max_failed_attempts,
            lockout_duration_minutes: self.lockout_duration_minutes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSettingsView {
    pub issuer: Option<String>,
    pub login_url: Option<String>,
    pub console_url: Option<String>,
    pub initialized_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSettingsView {
    pub oauth_version: OAuthProtocolVersion,
    pub require_pushed_authorization_requests: bool,
    pub pushed_authorization_request_lifetime_seconds: i64,
    pub device_authorization_request_lifetime_seconds: i64,
    pub device_authorization_polling_interval_seconds: i64,
    pub dynamic_registration_enabled: bool,
    pub access_token_lifetime_seconds: i64,
    pub id_token_lifetime_seconds: i64,
    pub refresh_token_lifetime_days: i64,
    pub authorization_code_lifetime_seconds: i64,
    pub version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHashingView {
    pub time_cost: u32,
    pub memory_cost_kib: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationSettingsView {
    pub breached_password_check_enabled: bool,
    pub identifier_enumeration_allowed: bool,
    pub email_sign_in_enabled: bool,
    pub password_reset_enabled: bool,
    pub registration_enabled: bool,
    pub password_max_age_days: u32,
    pub password_history_count: u32,
    pub password_min_length: u32,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub password_hashing: PasswordHashingView,
    pub version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSettingsView {
    pub session_lifetime_hours: u32,
    pub elevated_authentication_lifetime_minutes: u32,
    pub recent_authentication_lifetime_minutes: u32,
    pub login_lifetime_minutes: u32,
    pub version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSettingsView {
    pub general: GeneralSettingsView,
    pub protocol: ProtocolSettingsView,
    pub authentication: AuthenticationSettingsView,
    pub session: SessionSettingsView,
    pub email: EmailSettingsView,
}

impl From<&InstanceSettingsState> for InstanceSettingsView {
    fn from(state: &InstanceSettingsState) -> Self {
        let oidc = &state.openid_connect;
        let HashOptions::Argon2(argon2) = &state.password_hash;
        Self {
            general: GeneralSettingsView {
                issuer: state.app.domain.clone(),
                login_url: state.app.login_domain.clone(),
                console_url: state.app.console_domain.clone(),
                initialized_at: state.installation.initialized_at,
            },
            protocol: ProtocolSettingsView {
                oauth_version: oidc.oauth_version,
                require_pushed_authorization_requests: oidc
                    .pushed_authorization
                    .require_pushed_authorization_requests,
                pushed_authorization_request_lifetime_seconds: oidc
                    .pushed_authorization
                    .request_ttl_seconds,
                device_authorization_request_lifetime_seconds: oidc
                    .device_authorization
                    .request_ttl_seconds,
                device_authorization_polling_interval_seconds: oidc
                    .device_authorization
                    .polling_interval_seconds,
                dynamic_registration_enabled: oidc.dynamic_registration.enabled,
                access_token_lifetime_seconds: oidc.tokens.access_token_lifetime_seconds,
                id_token_lifetime_seconds: oidc.tokens.id_token_lifetime_seconds,
                refresh_token_lifetime_days: oidc.tokens.refresh_token_lifetime_days,
                authorization_code_lifetime_seconds: oidc
                    .tokens
                    .authorization_code_lifetime_seconds,
                version: InstanceSettingSection::Protocol.version(state),
            },
            authentication: AuthenticationSettingsView {
                breached_password_check_enabled: state.breached_password_check_enabled,
                identifier_enumeration_allowed: state.identifier_enumeration_allowed,
                email_sign_in_enabled: state.email_sign_in_enabled,
                password_reset_enabled: state.password_reset_enabled,
                registration_enabled: state.registration_enabled,
                password_max_age_days: state.password_max_age_days,
                password_history_count: state.password_history_count,
                password_min_length: state.password_min_length,
                max_failed_attempts: state.max_failed_attempts,
                lockout_duration_minutes: state.lockout_duration_minutes,
                password_hashing: PasswordHashingView {
                    time_cost: argon2.time_cost,
                    memory_cost_kib: argon2.memory_cost,
                    parallelism: argon2.parallelism,
                },
                version: InstanceSettingSection::Authentication.version(state),
            },
            session: SessionSettingsView {
                session_lifetime_hours: state.session.lifetime_hours,
                elevated_authentication_lifetime_minutes: state
                    .session
                    .elevated_authentication_lifetime_minutes,
                recent_authentication_lifetime_minutes: state
                    .session
                    .recent_authentication_lifetime_minutes,
                login_lifetime_minutes: state.session.login_lifetime_minutes,
                version: InstanceSettingSection::Session.version(state),
            },
            email: EmailSettingsView::from(state),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpdateProtocolSettingsCommand {
    pub oauth_version: OAuthProtocolVersion,
    pub require_pushed_authorization_requests: bool,
    pub pushed_authorization_request_lifetime_seconds: i64,
    pub device_authorization_request_lifetime_seconds: i64,
    pub device_authorization_polling_interval_seconds: i64,
    pub dynamic_registration_enabled: bool,
    pub access_token_lifetime_seconds: i64,
    pub id_token_lifetime_seconds: i64,
    pub refresh_token_lifetime_days: i64,
    pub authorization_code_lifetime_seconds: i64,
    pub expected_version: Uuid,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateAuthenticationSettingsCommand {
    pub breached_password_check_enabled: bool,
    pub identifier_enumeration_allowed: bool,
    pub email_sign_in_enabled: bool,
    pub password_reset_enabled: bool,
    pub registration_enabled: bool,
    pub password_max_age_days: u32,
    pub password_history_count: u32,
    pub password_min_length: u32,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub password_hashing: PasswordHashingView,
    pub expected_version: Uuid,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateSessionSettingsCommand {
    pub session_lifetime_hours: u32,
    pub elevated_authentication_lifetime_minutes: u32,
    pub recent_authentication_lifetime_minutes: u32,
    pub login_lifetime_minutes: u32,
    pub expected_version: Uuid,
    pub client_mutation_id: Option<String>,
}

/// Derives the replacement settings from the state read in the write transaction.
pub type SettingChangesBuilder =
    Box<dyn FnOnce(&InstanceSettingsState) -> Result<SettingChanges, AppError> + Send>;

/// The settings to store when the section's version still matches.
///
/// `build` derives the full replacement from the state read inside the write
/// transaction, so fields this surface does not edit keep their stored value.
pub struct UpdateInstanceSettingsTransaction {
    pub authority: RbacManagementAuthority,
    pub section: InstanceSettingSection,
    pub expected_version: Uuid,
    pub build: SettingChangesBuilder,
}

#[derive(Debug, Error)]
pub enum InstanceSettingRepositoryError {
    #[error("instance settings storage failed")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("management authorization failed")]
    Authorization(#[source] ManagementAuthorizationError),
    #[error("security audit write failed")]
    AuditFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("no recoverable authorization administrator would remain")]
    LastRecoverableAdministrator,
    #[error("settings section version conflict")]
    VersionConflict { current_version: Uuid },
    #[error("invalid settings change")]
    Invalid(#[source] AppError),
}

#[async_trait]
pub trait InstanceSettingRepository: Send + Sync {
    /// Reads the stored settings directly, not through the runtime snapshot,
    /// so an editor sees the version a write will compare against.
    async fn load(&self) -> Result<InstanceSettingsState, InstanceSettingRepositoryError>;

    async fn update(
        &self,
        transaction: UpdateInstanceSettingsTransaction,
    ) -> Result<InstanceSettingsState, InstanceSettingRepositoryError>;
}

pub struct InstanceSettingService {
    pub(super) repository: Arc<dyn InstanceSettingRepository>,
    runtime: Arc<dyn RefreshableSetting>,
    pub(super) events: Arc<dyn EventSink>,
    pub(super) email: Option<EmailManagementDependencies>,
}

impl InstanceSettingService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn InstanceSettingRepository>,
        runtime: Arc<dyn RefreshableSetting>,
    ) -> Self {
        Self {
            repository,
            runtime,
            events: Arc::new(NoopEventSink),
            email: None,
        }
    }

    /// Allow editing email delivery and templates and sending test email.
    #[must_use]
    pub fn with_email(mut self, dependencies: EmailManagementDependencies) -> Self {
        self.email = Some(dependencies);
        self
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    #[tracing::instrument(skip_all, name = "setting.instance.read")]
    pub async fn read(&self) -> Result<InstanceSettingsView, AppError> {
        let state = self.repository.load().await.map_err(map_repository_error)?;
        Ok(InstanceSettingsView::from(&state))
    }

    #[tracing::instrument(skip_all, name = "setting.protocol.update")]
    pub async fn update_protocol(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateProtocolSettingsCommand,
    ) -> Result<InstanceSettingsView, AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            PUSHED_AUTHORIZATION_LIFETIME_RANGE.check(
                command.pushed_authorization_request_lifetime_seconds,
                "pushed_authorization_request_lifetime_seconds",
            )?;
            DEVICE_AUTHORIZATION_LIFETIME_RANGE.check(
                command.device_authorization_request_lifetime_seconds,
                "device_authorization_request_lifetime_seconds",
            )?;
            DEVICE_POLLING_INTERVAL_RANGE.check(
                command.device_authorization_polling_interval_seconds,
                "device_authorization_polling_interval_seconds",
            )?;
            ACCESS_TOKEN_LIFETIME_RANGE.check(
                command.access_token_lifetime_seconds,
                "access_token_lifetime_seconds",
            )?;
            ID_TOKEN_LIFETIME_RANGE.check(
                command.id_token_lifetime_seconds,
                "id_token_lifetime_seconds",
            )?;
            REFRESH_TOKEN_LIFETIME_DAYS_RANGE.check(
                command.refresh_token_lifetime_days,
                "refresh_token_lifetime_days",
            )?;
            AUTHORIZATION_CODE_LIFETIME_RANGE.check(
                command.authorization_code_lifetime_seconds,
                "authorization_code_lifetime_seconds",
            )?;
            let build = move |state: &InstanceSettingsState| {
                let mut next = state.openid_connect.clone();
                next.oauth_version = command.oauth_version;
                next.pushed_authorization
                    .require_pushed_authorization_requests =
                    command.require_pushed_authorization_requests;
                next.pushed_authorization.request_ttl_seconds =
                    command.pushed_authorization_request_lifetime_seconds;
                next.device_authorization.request_ttl_seconds =
                    command.device_authorization_request_lifetime_seconds;
                next.device_authorization.polling_interval_seconds =
                    command.device_authorization_polling_interval_seconds;
                next.dynamic_registration.enabled = command.dynamic_registration_enabled;
                next.tokens.access_token_lifetime_seconds = command.access_token_lifetime_seconds;
                next.tokens.id_token_lifetime_seconds = command.id_token_lifetime_seconds;
                next.tokens.refresh_token_lifetime_days = command.refresh_token_lifetime_days;
                next.tokens.authorization_code_lifetime_seconds =
                    command.authorization_code_lifetime_seconds;
                Ok(SettingChanges::default().set_section(&next)?)
            };
            self.write(
                authority,
                InstanceSettingSection::Protocol,
                command.expected_version,
                Box::new(build),
            )
            .await
        }
        .await;
        self.emit(InstanceSettingSection::Protocol, &result);
        result
    }

    #[tracing::instrument(skip_all, name = "setting.authentication.update")]
    pub async fn update_authentication(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateAuthenticationSettingsCommand,
    ) -> Result<InstanceSettingsView, AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let hashing = &command.password_hashing;
            ARGON2_TIME_COST_RANGE
                .check(i64::from(hashing.time_cost), "password_hashing.time_cost")?;
            ARGON2_MEMORY_COST_RANGE.check(
                i64::from(hashing.memory_cost_kib),
                "password_hashing.memory_cost_kib",
            )?;
            ARGON2_PARALLELISM_RANGE.check(
                i64::from(hashing.parallelism),
                "password_hashing.parallelism",
            )?;
            let options = HashOptions::Argon2(Argon2Options {
                variant: Argon2Variant::Argon2id,
                version: Argon2Version::Argon2013,
                time_cost: hashing.time_cost,
                memory_cost: hashing.memory_cost_kib,
                parallelism: hashing.parallelism,
            });
            PASSWORD_MAX_AGE_DAYS_RANGE.check(
                i64::from(command.password_max_age_days),
                "password_max_age_days",
            )?;
            PASSWORD_HISTORY_COUNT_RANGE.check(
                i64::from(command.password_history_count),
                "password_history_count",
            )?;
            PASSWORD_MIN_LENGTH_RANGE.check(
                i64::from(command.password_min_length),
                "password_min_length",
            )?;
            MAX_FAILED_ATTEMPTS_RANGE.check(
                i64::from(command.max_failed_attempts),
                "max_failed_attempts",
            )?;
            LOCKOUT_DURATION_MINUTES_RANGE.check(
                i64::from(command.lockout_duration_minutes),
                "lockout_duration_minutes",
            )?;
            let max_age_days = command.password_max_age_days;
            let history_count = command.password_history_count;
            let password_min_length = command.password_min_length;
            let max_failed_attempts = command.max_failed_attempts;
            let lockout_duration_minutes = command.lockout_duration_minutes;
            let breached = command.breached_password_check_enabled;
            let enumeration = command.identifier_enumeration_allowed;
            let email_sign_in = command.email_sign_in_enabled;
            let password_reset = command.password_reset_enabled;
            let registration = command.registration_enabled;
            let build = move |state: &InstanceSettingsState| {
                // Turning email sign-in on needs a way to send it. Once on,
                // it stays saved if delivery is later turned off; it is then
                // simply not offered.
                if email_sign_in
                    && !state.email_sign_in_enabled
                    && !state.email_delivery.is_configured()
                {
                    return Err(instance::error::EmailDeliveryNotConfigured
                        .with_field("email_sign_in_enabled"));
                }
                if password_reset
                    && !state.password_reset_enabled
                    && !state.email_delivery.is_configured()
                {
                    return Err(instance::error::EmailDeliveryNotConfigured
                        .with_field("password_reset_enabled"));
                }
                if registration
                    && !state.registration_enabled
                    && !state.email_delivery.is_configured()
                {
                    return Err(instance::error::EmailDeliveryNotConfigured
                        .with_field("registration_enabled"));
                }
                Ok(SettingChanges::default()
                    .set::<PasswordHashSetting>(&options)?
                    .set::<BreachedPasswordCheckEnabledSetting>(&breached)?
                    .set::<IdentifierEnumerationAllowedSetting>(&enumeration)?
                    .set::<EmailSignInEnabledSetting>(&email_sign_in)?
                    .set::<PasswordResetEnabledSetting>(&password_reset)?
                    .set::<RegistrationEnabledSetting>(&registration)?
                    .set::<PasswordMaxAgeDaysSetting>(&max_age_days)?
                    .set::<PasswordHistoryCountSetting>(&history_count)?
                    .set::<PasswordMinLengthSetting>(&password_min_length)?
                    .set::<MaxFailedAttemptsSetting>(&max_failed_attempts)?
                    .set::<LockoutDurationMinutesSetting>(&lockout_duration_minutes)?)
            };
            self.write(
                authority,
                InstanceSettingSection::Authentication,
                command.expected_version,
                Box::new(build),
            )
            .await
        }
        .await;
        self.emit(InstanceSettingSection::Authentication, &result);
        result
    }

    #[tracing::instrument(skip_all, name = "setting.session.update")]
    pub async fn update_session(
        &self,
        authority: &RbacManagementAuthority,
        command: UpdateSessionSettingsCommand,
    ) -> Result<InstanceSettingsView, AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            SESSION_LIFETIME_HOURS_RANGE.check(
                i64::from(command.session_lifetime_hours),
                "session_lifetime_hours",
            )?;
            ELEVATED_AUTHENTICATION_LIFETIME_MINUTES_RANGE.check(
                i64::from(command.elevated_authentication_lifetime_minutes),
                "elevated_authentication_lifetime_minutes",
            )?;
            RECENT_AUTHENTICATION_LIFETIME_MINUTES_RANGE.check(
                i64::from(command.recent_authentication_lifetime_minutes),
                "recent_authentication_lifetime_minutes",
            )?;
            LOGIN_LIFETIME_MINUTES_RANGE.check(
                i64::from(command.login_lifetime_minutes),
                "login_lifetime_minutes",
            )?;
            let next = SessionSettings {
                lifetime_hours: command.session_lifetime_hours,
                elevated_authentication_lifetime_minutes: command
                    .elevated_authentication_lifetime_minutes,
                recent_authentication_lifetime_minutes: command
                    .recent_authentication_lifetime_minutes,
                login_lifetime_minutes: command.login_lifetime_minutes,
            };
            let build =
                move |_: &InstanceSettingsState| Ok(SettingChanges::default().set_section(&next)?);
            self.write(
                authority,
                InstanceSettingSection::Session,
                command.expected_version,
                Box::new(build),
            )
            .await
        }
        .await;
        self.emit(InstanceSettingSection::Session, &result);
        result
    }

    pub(super) async fn write(
        &self,
        authority: &RbacManagementAuthority,
        section: InstanceSettingSection,
        expected_version: Uuid,
        build: SettingChangesBuilder,
    ) -> Result<InstanceSettingsView, AppError> {
        let state = self
            .repository
            .update(UpdateInstanceSettingsTransaction {
                authority: authority.clone(),
                section,
                expected_version,
                build,
            })
            .await
            .map_err(map_repository_error)?;
        // Apply the change on this instance now; others pick it up on their
        // next refresh. The write itself has already committed.
        if let Err(error) = self.runtime.refresh_value().await {
            tracing::warn!(error = %error, "failed to refresh settings after update");
        }
        Ok(InstanceSettingsView::from(&state))
    }

    pub(super) fn emit(
        &self,
        section: InstanceSettingSection,
        result: &Result<InstanceSettingsView, AppError>,
    ) {
        let mut event = BusinessEvent::business(section.audit_action().into())
            .attribute("section", EventValue::Text(section.as_str().to_owned()));
        match result {
            Ok(_) => event = event.outcome("success"),
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        self.events.emit(event);
    }
}

pub(crate) fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    crate::authorization::validate_client_mutation_id_with(value, |max| {
        instance::error::InvalidClientMutationId::new(max).with_field("client_mutation_id")
    })
}

pub(super) fn map_repository_error(error: InstanceSettingRepositoryError) -> AppError {
    use InstanceSettingRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => instance::error::StorageFailed.with_source(error),
        Error::Authorization(source) => AppError::from(source),
        error @ Error::AuditFailed(_) => authorization::error::AuditWriteFailed.with_source(error),
        Error::LastRecoverableAdministrator => authorization::error::LastOwnerProtected.into(),
        Error::VersionConflict { current_version } => instance::error::VersionConflict::new()
            .current_version(current_version)
            .with_field("expected_version"),
        Error::Invalid(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> InstanceSettingsState {
        InstanceSettingsState {
            app: AppSettings::default(),
            installation: InstallationSettings::default(),
            openid_connect: OpenIdConnectSettings::default(),
            session: SessionSettings::default(),
            password_hash: PasswordHashSetting::default_value(),
            breached_password_check_enabled: true,
            identifier_enumeration_allowed: true,
            email_sign_in_enabled: false,
            password_reset_enabled: true,
            registration_enabled: false,
            password_max_age_days: 0,
            password_history_count: 0,
            password_min_length: 12,
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            email_delivery: EmailDeliverySettings::default(),
            email_policy: EmailPolicySettings::default(),
            email_templates: EmailTemplates::new(),
        }
    }

    use crate::setting::SettingDefinition;

    #[test]
    fn a_section_version_changes_only_with_its_own_values() {
        let before = state();
        let mut protocol_changed = before.clone();
        protocol_changed.openid_connect.dynamic_registration.enabled = true;
        let mut authentication_changed = before.clone();
        authentication_changed.breached_password_check_enabled = false;
        let mut enumeration_changed = before.clone();
        enumeration_changed.identifier_enumeration_allowed = false;
        let mut session_changed = before.clone();
        session_changed.session.lifetime_hours = 48;

        let protocol = InstanceSettingSection::Protocol;
        let authentication = InstanceSettingSection::Authentication;
        let session = InstanceSettingSection::Session;
        assert_ne!(
            protocol.version(&before),
            protocol.version(&protocol_changed)
        );
        assert_eq!(
            authentication.version(&before),
            authentication.version(&protocol_changed)
        );
        assert_eq!(session.version(&before), session.version(&protocol_changed));
        assert_ne!(
            authentication.version(&before),
            authentication.version(&authentication_changed)
        );
        assert_ne!(
            authentication.version(&before),
            authentication.version(&enumeration_changed)
        );
        assert_ne!(session.version(&before), session.version(&session_changed));
        assert_eq!(protocol.version(&before), protocol.version(&state()));
    }

    #[test]
    fn out_of_range_values_name_their_field_and_bounds() {
        let error = DEVICE_POLLING_INTERVAL_RANGE
            .check(0, "device_authorization_polling_interval_seconds")
            .unwrap_err();
        assert_eq!(
            error.code(),
            crate::error::codes::instance::InstanceErrorCode::SettingOutOfRange as u32
        );
        assert!(DEVICE_POLLING_INTERVAL_RANGE.check(60, "field").is_ok());
        assert!(DEVICE_POLLING_INTERVAL_RANGE.check(61, "field").is_err());
    }

    struct StubSettingRepository {
        state: std::sync::Mutex<InstanceSettingsState>,
        recorded: std::sync::Mutex<Vec<(InstanceSettingSection, Vec<(String, serde_json::Value)>)>>,
    }

    impl StubSettingRepository {
        fn new(initial: InstanceSettingsState) -> Self {
            Self {
                state: std::sync::Mutex::new(initial),
                recorded: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl InstanceSettingRepository for StubSettingRepository {
        async fn load(&self) -> Result<InstanceSettingsState, InstanceSettingRepositoryError> {
            Ok(self.state.lock().unwrap().clone())
        }

        async fn update(
            &self,
            transaction: UpdateInstanceSettingsTransaction,
        ) -> Result<InstanceSettingsState, InstanceSettingRepositoryError> {
            let mut guard = self.state.lock().unwrap();
            let current_version = transaction.section.version(&guard);
            if current_version != transaction.expected_version {
                return Err(InstanceSettingRepositoryError::VersionConflict { current_version });
            }
            let changes =
                (transaction.build)(&guard).map_err(InstanceSettingRepositoryError::Invalid)?;
            let mut pairs = Vec::new();
            for (key, value) in changes {
                match key.as_str() {
                    "auth.session.lifetime_hours" => {
                        guard.session.lifetime_hours =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "auth.session.elevated_authentication_lifetime_minutes" => {
                        guard.session.elevated_authentication_lifetime_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "auth.session.recent_authentication_lifetime_minutes" => {
                        guard.session.recent_authentication_lifetime_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "auth.session.login_lifetime_minutes" => {
                        guard.session.login_lifetime_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "openid_connect.tokens" => {
                        guard.openid_connect.tokens =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "auth.password.min_length" => {
                        guard.password_min_length = serde_json::from_value(value.clone()).unwrap();
                    }
                    "auth.login.max_failed_attempts" => {
                        guard.max_failed_attempts = serde_json::from_value(value.clone()).unwrap();
                    }
                    "auth.login.lockout_duration_minutes" => {
                        guard.lockout_duration_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.sign_in_code_lifetime_minutes" => {
                        guard.email_policy.sign_in_code_lifetime_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.password_reset_lifetime_minutes" => {
                        guard.email_policy.password_reset_lifetime_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.registration_lifetime_minutes" => {
                        guard.email_policy.registration_lifetime_minutes =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.email_verification_lifetime_hours" => {
                        guard.email_policy.email_verification_lifetime_hours =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.user_invitation_lifetime_days" => {
                        guard.email_policy.user_invitation_lifetime_days =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.resend_interval_seconds" => {
                        guard.email_policy.resend_interval_seconds =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.login_max_sends" => {
                        guard.email_policy.login_max_sends =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.verification_max_sends" => {
                        guard.email_policy.verification_max_sends =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    "email.policy.verification_send_window_hours" => {
                        guard.email_policy.verification_send_window_hours =
                            serde_json::from_value(value.clone()).unwrap();
                    }
                    _ => {}
                }
                pairs.push((key, value));
            }
            self.recorded
                .lock()
                .unwrap()
                .push((transaction.section, pairs));
            Ok(guard.clone())
        }
    }

    struct NoopRuntimeSettings;

    #[async_trait]
    impl RefreshableSetting for NoopRuntimeSettings {
        fn key(&self) -> &'static str {
            "*"
        }

        async fn refresh_value(&self) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn test_authority() -> RbacManagementAuthority {
        use identity_domain::authorization::{
            ActorContext, HumanAuthenticationContext, ManagementScope, PolicyVersion, RequestId,
        };
        use identity_domain::user::UserOid;
        RbacManagementAuthority::new(
            ActorContext::for_user(
                UserOid(Uuid::new_v4()),
                HumanAuthenticationContext::aal2(Some(Utc::now())),
                RequestId::new("req-settings-test").unwrap(),
                None,
            ),
            [ManagementScope::SettingsWrite].into_iter().collect(),
            None,
            Uuid::new_v4(),
            PolicyVersion(Uuid::new_v4()),
        )
    }

    #[tokio::test]
    async fn update_session_persists_values_rotates_version_and_rejects_out_of_range() {
        let initial = state();
        let expected_version = InstanceSettingSection::Session.version(&initial);
        let repo = Arc::new(StubSettingRepository::new(initial));
        let service = InstanceSettingService::new(repo.clone(), Arc::new(NoopRuntimeSettings));
        let authority = test_authority();

        let bad_cases = [
            (0, 60, 5, 5, "session_lifetime_hours"),
            (168, 4, 5, 5, "elevated_authentication_lifetime_minutes"),
            (168, 60, 61, 5, "recent_authentication_lifetime_minutes"),
            (168, 60, 5, 0, "login_lifetime_minutes"),
        ];
        for (hours, elevated, recent, login, field) in bad_cases {
            let err = service
                .update_session(
                    &authority,
                    UpdateSessionSettingsCommand {
                        session_lifetime_hours: hours,
                        elevated_authentication_lifetime_minutes: elevated,
                        recent_authentication_lifetime_minutes: recent,
                        login_lifetime_minutes: login,
                        expected_version,
                        client_mutation_id: None,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.code(),
                crate::error::codes::instance::InstanceErrorCode::SettingOutOfRange as u32
            );
            assert_eq!(err.validation().unwrap().fields()[0].field(), field);
        }

        let updated = service
            .update_session(
                &authority,
                UpdateSessionSettingsCommand {
                    session_lifetime_hours: 72,
                    elevated_authentication_lifetime_minutes: 30,
                    recent_authentication_lifetime_minutes: 10,
                    login_lifetime_minutes: 15,
                    expected_version,
                    client_mutation_id: Some("session-1".to_owned()),
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.session.session_lifetime_hours, 72);
        assert_eq!(updated.session.elevated_authentication_lifetime_minutes, 30);
        assert_eq!(updated.session.recent_authentication_lifetime_minutes, 10);
        assert_eq!(updated.session.login_lifetime_minutes, 15);
        assert_ne!(updated.session.version, expected_version);
        let recorded = repo.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, InstanceSettingSection::Session);
    }

    #[tokio::test]
    async fn update_protocol_persists_token_lifetimes_and_rejects_out_of_range() {
        let initial = state();
        let expected_version = InstanceSettingSection::Protocol.version(&initial);
        let repo = Arc::new(StubSettingRepository::new(initial));
        let service = InstanceSettingService::new(repo, Arc::new(NoopRuntimeSettings));
        let authority = test_authority();

        let bad_cases = [
            (59, 3_600, 30, 600, "access_token_lifetime_seconds"),
            (3_600, 86_401, 30, 600, "id_token_lifetime_seconds"),
            (3_600, 3_600, 0, 600, "refresh_token_lifetime_days"),
            (3_600, 3_600, 30, 601, "authorization_code_lifetime_seconds"),
        ];
        for (access, id, refresh, code, field) in bad_cases {
            let err = service
                .update_protocol(
                    &authority,
                    UpdateProtocolSettingsCommand {
                        oauth_version: OAuthProtocolVersion::V2_0,
                        require_pushed_authorization_requests: false,
                        pushed_authorization_request_lifetime_seconds: 90,
                        device_authorization_request_lifetime_seconds: 600,
                        device_authorization_polling_interval_seconds: 5,
                        dynamic_registration_enabled: false,
                        access_token_lifetime_seconds: access,
                        id_token_lifetime_seconds: id,
                        refresh_token_lifetime_days: refresh,
                        authorization_code_lifetime_seconds: code,
                        expected_version,
                        client_mutation_id: None,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.validation().unwrap().fields()[0].field(), field);
        }

        let updated = service
            .update_protocol(
                &authority,
                UpdateProtocolSettingsCommand {
                    oauth_version: OAuthProtocolVersion::V2_1,
                    require_pushed_authorization_requests: true,
                    pushed_authorization_request_lifetime_seconds: 120,
                    device_authorization_request_lifetime_seconds: 900,
                    device_authorization_polling_interval_seconds: 10,
                    dynamic_registration_enabled: false,
                    access_token_lifetime_seconds: 1_800,
                    id_token_lifetime_seconds: 900,
                    refresh_token_lifetime_days: 14,
                    authorization_code_lifetime_seconds: 120,
                    expected_version,
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.protocol.access_token_lifetime_seconds, 1_800);
        assert_eq!(updated.protocol.id_token_lifetime_seconds, 900);
        assert_eq!(updated.protocol.refresh_token_lifetime_days, 14);
        assert_eq!(updated.protocol.authorization_code_lifetime_seconds, 120);
        assert_ne!(updated.protocol.version, expected_version);
    }

    #[tokio::test]
    async fn update_authentication_persists_lockout_and_min_length_and_rejects_out_of_range() {
        let initial = state();
        let expected_version = InstanceSettingSection::Authentication.version(&initial);
        let HashOptions::Argon2(argon2) = &initial.password_hash;
        let hashing = PasswordHashingView {
            time_cost: argon2.time_cost,
            memory_cost_kib: argon2.memory_cost,
            parallelism: argon2.parallelism,
        };
        let repo = Arc::new(StubSettingRepository::new(initial));
        let service = InstanceSettingService::new(repo, Arc::new(NoopRuntimeSettings));
        let authority = test_authority();

        let bad_cases = [
            (7, 5, 15, "password_min_length"),
            (12, 2, 15, "max_failed_attempts"),
            (12, 5, 1_441, "lockout_duration_minutes"),
        ];
        for (min_length, max_attempts, lockout_minutes, field) in bad_cases {
            let err = service
                .update_authentication(
                    &authority,
                    UpdateAuthenticationSettingsCommand {
                        breached_password_check_enabled: true,
                        identifier_enumeration_allowed: true,
                        email_sign_in_enabled: false,
                        password_reset_enabled: true,
                        registration_enabled: false,
                        password_max_age_days: 0,
                        password_history_count: 0,
                        password_min_length: min_length,
                        max_failed_attempts: max_attempts,
                        lockout_duration_minutes: lockout_minutes,
                        password_hashing: hashing.clone(),
                        expected_version,
                        client_mutation_id: None,
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(err.validation().unwrap().fields()[0].field(), field);
        }

        let updated = service
            .update_authentication(
                &authority,
                UpdateAuthenticationSettingsCommand {
                    breached_password_check_enabled: true,
                    identifier_enumeration_allowed: false,
                    email_sign_in_enabled: false,
                    password_reset_enabled: true,
                    registration_enabled: false,
                    password_max_age_days: 90,
                    password_history_count: 3,
                    password_min_length: 16,
                    max_failed_attempts: 8,
                    lockout_duration_minutes: 30,
                    password_hashing: hashing,
                    expected_version,
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.authentication.password_min_length, 16);
        assert_eq!(updated.authentication.max_failed_attempts, 8);
        assert_eq!(updated.authentication.lockout_duration_minutes, 30);
        assert_ne!(updated.authentication.version, expected_version);
    }

    #[tokio::test]
    async fn update_email_policy_persists_values_rotates_version_and_rejects_out_of_range() {
        use crate::setting::email::UpdateEmailPolicyCommand;

        let initial = state();
        let expected_version = InstanceSettingSection::EmailPolicy.version(&initial);
        let repo = Arc::new(StubSettingRepository::new(initial));
        let service = InstanceSettingService::new(repo.clone(), Arc::new(NoopRuntimeSettings));
        let authority = test_authority();

        let err = service
            .update_email_policy(
                &authority,
                UpdateEmailPolicyCommand {
                    sign_in_code_lifetime_minutes: 0,
                    password_reset_lifetime_minutes: 15,
                    registration_lifetime_minutes: 15,
                    email_verification_lifetime_hours: 24,
                    user_invitation_lifetime_days: 7,
                    resend_interval_seconds: 60,
                    login_max_sends: 5,
                    verification_max_sends: 5,
                    verification_send_window_hours: 24,
                    expected_version,
                    client_mutation_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            crate::error::codes::instance::InstanceErrorCode::SettingOutOfRange as u32
        );
        assert_eq!(
            err.validation().unwrap().fields()[0].field(),
            "sign_in_code_lifetime_minutes"
        );

        let updated = service
            .update_email_policy(
                &authority,
                UpdateEmailPolicyCommand {
                    sign_in_code_lifetime_minutes: 20,
                    password_reset_lifetime_minutes: 30,
                    registration_lifetime_minutes: 45,
                    email_verification_lifetime_hours: 48,
                    user_invitation_lifetime_days: 14,
                    resend_interval_seconds: 90,
                    login_max_sends: 8,
                    verification_max_sends: 10,
                    verification_send_window_hours: 12,
                    expected_version,
                    client_mutation_id: Some("email-policy-1".to_owned()),
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.email.policy.sign_in_code_lifetime_minutes, 20);
        assert_eq!(updated.email.policy.password_reset_lifetime_minutes, 30);
        assert_eq!(updated.email.policy.registration_lifetime_minutes, 45);
        assert_eq!(updated.email.policy.email_verification_lifetime_hours, 48);
        assert_eq!(updated.email.policy.user_invitation_lifetime_days, 14);
        assert_eq!(updated.email.policy.resend_interval_seconds, 90);
        assert_eq!(updated.email.policy.login_max_sends, 8);
        assert_eq!(updated.email.policy.verification_max_sends, 10);
        assert_eq!(updated.email.policy.verification_send_window_hours, 12);
        assert_ne!(updated.email.policy.version, expected_version);
        let recorded = repo.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, InstanceSettingSection::EmailPolicy);
    }
}
