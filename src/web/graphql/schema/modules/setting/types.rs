use async_graphql::{InputObject, Object, SimpleObject};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    setting::management::{
        ARGON2_MEMORY_COST_RANGE, ARGON2_PARALLELISM_RANGE, ARGON2_TIME_COST_RANGE,
        AuthenticationSettingsView, DEVICE_AUTHORIZATION_LIFETIME_RANGE,
        DEVICE_POLLING_INTERVAL_RANGE, GeneralSettingsView, InstanceSettingsView,
        PUSHED_AUTHORIZATION_LIFETIME_RANGE, ProtocolSettingsView, SettingRange,
    },
};
use identity_domain::authorization::ManagementScope;
use uuid::Uuid;

use crate::graphql::schema::{
    access::access, management_guard::ManagementGuard, modules::client::types::ClientOAuthVersion,
};

pub(crate) struct InstanceSettings {
    view: InstanceSettingsView,
}

impl From<InstanceSettingsView> for InstanceSettings {
    fn from(view: InstanceSettingsView) -> Self {
        Self { view }
    }
}

#[Object]
impl InstanceSettings {
    /// Where this instance is served. Set at installation; read-only.
    async fn general(&self) -> GeneralSettings {
        GeneralSettings::from(&self.view.general)
    }

    async fn protocol(&self) -> ProtocolSettings {
        ProtocolSettings::from(&self.view.protocol)
    }

    async fn authentication(&self) -> AuthenticationSettings {
        AuthenticationSettings::from(&self.view.authentication)
    }
}

#[derive(SimpleObject)]
pub(crate) struct GeneralSettings {
    issuer: Option<String>,
    login_url: Option<String>,
    console_url: Option<String>,
    initialized_at: Option<DateTime<Utc>>,
}

impl From<&GeneralSettingsView> for GeneralSettings {
    fn from(view: &GeneralSettingsView) -> Self {
        Self {
            issuer: view.issuer.clone(),
            login_url: view.login_url.clone(),
            console_url: view.console_url.clone(),
            initialized_at: view.initialized_at,
        }
    }
}

/// Inclusive bounds the instance accepts for one numeric setting.
#[derive(SimpleObject)]
pub(crate) struct IntRange {
    min: i32,
    max: i32,
}

impl From<SettingRange> for IntRange {
    fn from(range: SettingRange) -> Self {
        Self {
            min: i32::try_from(range.min).unwrap_or(i32::MIN),
            max: i32::try_from(range.max).unwrap_or(i32::MAX),
        }
    }
}

fn int(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

pub(crate) struct ProtocolSettings {
    view: ProtocolSettingsView,
}

impl From<&ProtocolSettingsView> for ProtocolSettings {
    fn from(view: &ProtocolSettingsView) -> Self {
        Self { view: view.clone() }
    }
}

#[Object]
impl ProtocolSettings {
    /// OAuth rules for clients without their own override.
    async fn oauth_version(&self) -> ClientOAuthVersion {
        self.view.oauth_version.into()
    }

    async fn require_pushed_authorization_requests(&self) -> bool {
        self.view.require_pushed_authorization_requests
    }

    async fn pushed_authorization_request_lifetime_seconds(&self) -> i32 {
        int(self.view.pushed_authorization_request_lifetime_seconds)
    }

    async fn pushed_authorization_request_lifetime_range(&self) -> IntRange {
        PUSHED_AUTHORIZATION_LIFETIME_RANGE.into()
    }

    async fn device_authorization_request_lifetime_seconds(&self) -> i32 {
        int(self.view.device_authorization_request_lifetime_seconds)
    }

    async fn device_authorization_request_lifetime_range(&self) -> IntRange {
        DEVICE_AUTHORIZATION_LIFETIME_RANGE.into()
    }

    async fn device_authorization_polling_interval_seconds(&self) -> i32 {
        int(self.view.device_authorization_polling_interval_seconds)
    }

    async fn device_authorization_polling_interval_range(&self) -> IntRange {
        DEVICE_POLLING_INTERVAL_RANGE.into()
    }

    /// Whether anyone may register a client at the registration endpoint.
    async fn dynamic_registration_enabled(&self) -> bool {
        self.view.dynamic_registration_enabled
    }

    /// UUID optimistic-lock version of this section.
    async fn version(&self) -> Uuid {
        self.view.version
    }
}

pub(crate) struct AuthenticationSettings {
    view: AuthenticationSettingsView,
}

impl From<&AuthenticationSettingsView> for AuthenticationSettings {
    fn from(view: &AuthenticationSettingsView) -> Self {
        Self { view: view.clone() }
    }
}

#[Object]
impl AuthenticationSettings {
    /// Reject passwords that appear in known breaches.
    async fn breached_password_check_enabled(&self) -> bool {
        self.view.breached_password_check_enabled
    }

    /// Argon2id cost for newly stored password hashes.
    async fn password_hashing(&self) -> PasswordHashing {
        let hashing = &self.view.password_hashing;
        PasswordHashing {
            time_cost: hashing.time_cost,
            memory_cost_kib: hashing.memory_cost_kib,
            parallelism: hashing.parallelism,
        }
    }

    /// UUID optimistic-lock version of this section.
    async fn version(&self) -> Uuid {
        self.view.version
    }
}

pub(crate) struct PasswordHashing {
    time_cost: u32,
    memory_cost_kib: u32,
    parallelism: u32,
}

#[Object]
impl PasswordHashing {
    async fn time_cost(&self) -> u32 {
        self.time_cost
    }

    async fn time_cost_range(&self) -> IntRange {
        ARGON2_TIME_COST_RANGE.into()
    }

    async fn memory_cost_kib(&self) -> u32 {
        self.memory_cost_kib
    }

    async fn memory_cost_kib_range(&self) -> IntRange {
        ARGON2_MEMORY_COST_RANGE.into()
    }

    async fn parallelism(&self) -> u32 {
        self.parallelism
    }

    async fn parallelism_range(&self) -> IntRange {
        ARGON2_PARALLELISM_RANGE.into()
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateProtocolSettingsInput {
    pub oauth_version: ClientOAuthVersion,
    pub require_pushed_authorization_requests: bool,
    pub pushed_authorization_request_lifetime_seconds: i32,
    pub device_authorization_request_lifetime_seconds: i32,
    pub device_authorization_polling_interval_seconds: i32,
    pub dynamic_registration_enabled: bool,
    pub expected_version: Uuid,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct PasswordHashingInput {
    pub time_cost: u32,
    pub memory_cost_kib: u32,
    pub parallelism: u32,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateAuthenticationSettingsInput {
    pub breached_password_check_enabled: bool,
    pub password_hashing: PasswordHashingInput,
    pub expected_version: Uuid,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct InstanceSettingsPayload {
    settings: InstanceSettingsView,
    client_mutation_id: Option<String>,
}

impl InstanceSettingsPayload {
    pub(crate) fn new(settings: InstanceSettingsView, client_mutation_id: Option<String>) -> Self {
        Self {
            settings,
            client_mutation_id,
        }
    }
}

#[Object]
impl InstanceSettingsPayload {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsRead))
    )]
    async fn settings(&self) -> Option<InstanceSettings> {
        Some(InstanceSettings::from(self.settings.clone()))
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}
