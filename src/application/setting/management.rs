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

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::{openid_connect::OAuthProtocolVersion, rbac::builtin::deterministic_oid};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use super::{
    AppSettings, BreachedPasswordCheckEnabledSetting, InstallationSettings, OpenIdConnectSettings,
    PasswordHashSetting, SettingChanges, runtime::RefreshableSetting,
};
use crate::{
    authentication::password::HashOptions,
    authorization::ManagementAuthorizationError,
    error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, instance::InstanceErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::RbacManagementAuthority,
    user::model::{Argon2Options, Argon2Variant, Argon2Version},
};

pub const MAX_CLIENT_MUTATION_ID_LENGTH: usize = 255;

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

    fn check(self, value: i64, field: &'static str) -> Result<(), AppError> {
        if (self.min..=self.max).contains(&value) {
            return Ok(());
        }
        Err(AppError::from_code(InstanceErrorCode::SettingOutOfRange)
            .with_param("min", self.min.to_string())
            .with_param("max", self.max.to_string())
            .with_field(field))
    }
}

pub const PUSHED_AUTHORIZATION_LIFETIME_RANGE: SettingRange = SettingRange::new(10, 600);
pub const DEVICE_AUTHORIZATION_LIFETIME_RANGE: SettingRange = SettingRange::new(60, 3_600);
pub const DEVICE_POLLING_INTERVAL_RANGE: SettingRange = SettingRange::new(1, 60);
pub const ARGON2_TIME_COST_RANGE: SettingRange = SettingRange::new(1, 10);
/// KiB. The lower bound follows the commonly recommended Argon2id minimum.
pub const ARGON2_MEMORY_COST_RANGE: SettingRange = SettingRange::new(19_456, 1_048_576);
pub const ARGON2_PARALLELISM_RANGE: SettingRange = SettingRange::new(1, 16);

/// One editable group of instance settings, written and versioned as a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceSettingSection {
    Protocol,
    Authentication,
}

impl InstanceSettingSection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Authentication => "authentication",
        }
    }

    #[must_use]
    pub const fn audit_action(self) -> &'static str {
        match self {
            Self::Protocol => "setting.protocol.update",
            Self::Authentication => "setting.authentication.update",
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
            Self::Authentication => content_version(
                self,
                &(&state.password_hash, state.breached_password_check_enabled),
            ),
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
    pub password_hash: HashOptions,
    pub breached_password_check_enabled: bool,
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
    pub password_hashing: PasswordHashingView,
    pub version: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSettingsView {
    pub general: GeneralSettingsView,
    pub protocol: ProtocolSettingsView,
    pub authentication: AuthenticationSettingsView,
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
                version: InstanceSettingSection::Protocol.version(state),
            },
            authentication: AuthenticationSettingsView {
                breached_password_check_enabled: state.breached_password_check_enabled,
                password_hashing: PasswordHashingView {
                    time_cost: argon2.time_cost,
                    memory_cost_kib: argon2.memory_cost,
                    parallelism: argon2.parallelism,
                },
                version: InstanceSettingSection::Authentication.version(state),
            },
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
    pub expected_version: Uuid,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateAuthenticationSettingsCommand {
    pub breached_password_check_enabled: bool,
    pub password_hashing: PasswordHashingView,
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
    repository: Arc<dyn InstanceSettingRepository>,
    runtime: Arc<dyn RefreshableSetting>,
    events: Arc<dyn EventSink>,
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
        }
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
                "pushedAuthorizationRequestLifetimeSeconds",
            )?;
            DEVICE_AUTHORIZATION_LIFETIME_RANGE.check(
                command.device_authorization_request_lifetime_seconds,
                "deviceAuthorizationRequestLifetimeSeconds",
            )?;
            DEVICE_POLLING_INTERVAL_RANGE.check(
                command.device_authorization_polling_interval_seconds,
                "deviceAuthorizationPollingIntervalSeconds",
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
                .check(i64::from(hashing.time_cost), "passwordHashing.timeCost")?;
            ARGON2_MEMORY_COST_RANGE.check(
                i64::from(hashing.memory_cost_kib),
                "passwordHashing.memoryCostKib",
            )?;
            ARGON2_PARALLELISM_RANGE.check(
                i64::from(hashing.parallelism),
                "passwordHashing.parallelism",
            )?;
            let options = HashOptions::Argon2(Argon2Options {
                variant: Argon2Variant::Argon2id,
                version: Argon2Version::Argon2013,
                time_cost: hashing.time_cost,
                memory_cost: hashing.memory_cost_kib,
                parallelism: hashing.parallelism,
            });
            let breached = command.breached_password_check_enabled;
            let build = move |_: &InstanceSettingsState| {
                Ok(SettingChanges::default()
                    .set::<PasswordHashSetting>(&options)?
                    .set::<BreachedPasswordCheckEnabledSetting>(&breached)?)
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

    async fn write(
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

    fn emit(
        &self,
        section: InstanceSettingSection,
        result: &Result<InstanceSettingsView, AppError>,
    ) {
        let mut event = BusinessEvent::business(section.audit_action())
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
    if value.is_some_and(|value| value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH) {
        return Err(
            AppError::from_code(InstanceErrorCode::InvalidClientMutationId)
                .with_param("max", MAX_CLIENT_MUTATION_ID_LENGTH.to_string())
                .with_field("clientMutationId"),
        );
    }
    Ok(())
}

fn map_repository_error(error: InstanceSettingRepositoryError) -> AppError {
    use InstanceSettingRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => {
            AppError::from_code(InstanceErrorCode::StorageFailed).with_source(error)
        }
        Error::Authorization(source) => AppError::from(source),
        error @ Error::AuditFailed(_) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(error)
        }
        Error::LastRecoverableAdministrator => {
            AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
        }
        Error::VersionConflict { current_version } => {
            AppError::from_code(InstanceErrorCode::VersionConflict)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion")
        }
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
            password_hash: PasswordHashSetting::default_value(),
            breached_password_check_enabled: true,
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

        let protocol = InstanceSettingSection::Protocol;
        let authentication = InstanceSettingSection::Authentication;
        assert_ne!(
            protocol.version(&before),
            protocol.version(&protocol_changed)
        );
        assert_eq!(
            authentication.version(&before),
            authentication.version(&protocol_changed)
        );
        assert_ne!(
            authentication.version(&before),
            authentication.version(&authentication_changed)
        );
        assert_eq!(protocol.version(&before), protocol.version(&state()));
    }

    #[test]
    fn out_of_range_values_name_their_field_and_bounds() {
        let error = DEVICE_POLLING_INTERVAL_RANGE
            .check(0, "deviceAuthorizationPollingIntervalSeconds")
            .unwrap_err();
        assert_eq!(error.code(), InstanceErrorCode::SettingOutOfRange as u32);
        assert!(DEVICE_POLLING_INTERVAL_RANGE.check(60, "field").is_ok());
        assert!(DEVICE_POLLING_INTERVAL_RANGE.check(61, "field").is_err());
    }
}
