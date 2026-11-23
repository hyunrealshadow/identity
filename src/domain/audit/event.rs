//! Typed security audit events.
//!
//! Every enumerable attribute of an audit record is a Rust enum whose stable
//! persisted value comes from its `strum` serialization. Call sites name an
//! [`AuditAction`]; the category and target kind follow from it, so a record
//! cannot pair an action with the wrong object type.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::{AsRefStr, Display, EnumIter, EnumString, IntoStaticStr};
use uuid::Uuid;

use crate::{
    authorization::{ActorContext, ActorPrincipal},
    rbac::LocalizedMetadata,
};

/// Which audit log an event belongs to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, AsRefStr, IntoStaticStr, EnumString, EnumIter,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditCategory {
    /// Instance administration: users, clients, roles, groups, keys, settings.
    Management,
    /// A person's changes to their own account and credentials.
    Account,
    /// Sign-in, lockout, and session lifecycle.
    SignIn,
    /// Consent, device approvals, and token revocation.
    Authorization,
}

/// Result of the audited attempt.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, AsRefStr, IntoStaticStr, EnumString, EnumIter,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditOutcome {
    Success,
    Failure,
}

/// Why an attempt failed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, AsRefStr, IntoStaticStr, EnumString, EnumIter,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditFailureReason {
    InvalidCredential,
    InvalidOtp,
    InvalidRecoveryCode,
    ReplayDetected,
    /// The entered identifier matches no account; the identifier is not kept.
    UnknownAccount,
    AccountLocked,
    AccountDisabled,
}

/// Who performed the action.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, AsRefStr, IntoStaticStr, EnumString, EnumIter,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditActorKind {
    User,
    Client,
    /// Identity itself: seed reconciliation and installation bootstrap.
    System,
    /// A caller that has not authenticated, such as a failed sign-in.
    Anonymous,
}

/// Type of the object an action applies to.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Display,
    AsRefStr,
    IntoStaticStr,
    EnumString,
    EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditTargetKind {
    User,
    Client,
    Role,
    Group,
    Scope,
    Resource,
    Key,
    Setting,
    Session,
    Passkey,
    DeviceAuthorization,
}

/// How a person authenticated, derived from the session's `amr` values.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Display,
    AsRefStr,
    IntoStaticStr,
    EnumString,
    EnumIter,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditAuthMethod {
    Password,
    Otp,
    Passkey,
    RecoveryCode,
}

impl AuditAuthMethod {
    /// Maps one RFC 8176 `amr` value; aggregate markers such as `mfa` have no
    /// method of their own.
    #[must_use]
    pub fn from_amr(value: &str) -> Option<Self> {
        match value {
            crate::auth::AMR_PASSWORD => Some(Self::Password),
            crate::auth::AMR_OTP => Some(Self::Otp),
            crate::auth::AMR_PASSKEY => Some(Self::Passkey),
            crate::auth::AMR_RECOVERY_CODE => Some(Self::RecoveryCode),
            _ => None,
        }
    }

    /// Distinct methods of an `amr` list in a stable order.
    #[must_use]
    pub fn from_amr_values<S: AsRef<str>>(values: &[S]) -> Vec<Self> {
        let mut methods: Vec<Self> = values
            .iter()
            .filter_map(|value| Self::from_amr(value.as_ref()))
            .collect();
        methods.sort_unstable();
        methods.dedup();
        methods
    }
}

/// A changed attribute of an audited object.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Display,
    AsRefStr,
    IntoStaticStr,
    EnumString,
    EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum AuditField {
    Name,
    Names,
    Description,
    Descriptions,
    Enabled,
    Username,
    Email,
    EmailVerified,
    PhoneNumber,
    GivenName,
    FamilyName,
    MiddleName,
    Nickname,
    Profile,
    Picture,
    Website,
    Gender,
    Birthdate,
    TimeZone,
    Locale,
    Address,
    Preferences,
    Password,
    Totp,
    RecoveryCodes,
    Passkey,
    Roles,
    Permissions,
    Members,
    Scopes,
    Settings,
}

macro_rules! audit_actions {
    ($( $variant:ident => $category:ident, $target:ident; )+) => {
        /// A stable, public audit action named object first, then verb. Its
        /// persisted value is the snake_case variant name, such as
        /// `user_role_grant`, so `user_*` selects every action on users.
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, Display, AsRefStr, IntoStaticStr,
            EnumString, EnumIter,
        )]
        #[strum(serialize_all = "snake_case", ascii_case_insensitive)]
        pub enum AuditAction {
            $( $variant, )+
        }

        impl AuditAction {
            #[must_use]
            pub const fn category(self) -> AuditCategory {
                match self { $( Self::$variant => AuditCategory::$category, )+ }
            }

            #[must_use]
            pub const fn target_kind(self) -> AuditTargetKind {
                match self { $( Self::$variant => AuditTargetKind::$target, )+ }
            }
        }
    };
}

audit_actions! {
    UserCreate => Management, User;
    UserUpdate => Management, User;
    UserEnable => Management, User;
    UserDisable => Management, User;
    UserUnlock => Management, User;
    UserRoleGrant => Management, User;
    UserRoleRevoke => Management, User;
    GroupCreate => Management, Group;
    GroupUpdate => Management, Group;
    GroupEnable => Management, Group;
    GroupDisable => Management, Group;
    GroupDelete => Management, Group;
    GroupMemberAdd => Management, Group;
    GroupMemberRemove => Management, Group;
    GroupRoleUpdate => Management, Group;
    RoleCreate => Management, Role;
    RoleUpdate => Management, Role;
    RoleEnable => Management, Role;
    RoleDisable => Management, Role;
    RolePermissionUpdate => Management, Role;
    ResourceCreate => Management, Resource;
    ResourceUpdate => Management, Resource;
    ResourceEnable => Management, Resource;
    ResourceDisable => Management, Resource;
    ScopeCreate => Management, Scope;
    ScopeUpdate => Management, Scope;
    ScopeEnable => Management, Scope;
    ScopeDisable => Management, Scope;
    ClientCreate => Management, Client;
    ClientUpdate => Management, Client;
    ClientDelete => Management, Client;
    ClientEnable => Management, Client;
    ClientDisable => Management, Client;
    ClientSecretCreate => Management, Client;
    ClientSecretRotate => Management, Client;
    ClientPublicKeyAdd => Management, Client;
    ClientJwksUriSet => Management, Client;
    ClientCredentialRevoke => Management, Client;
    ClientScopeUpdate => Management, Client;
    ClientRegister => Management, Client;
    ClientRegistrationUpdate => Management, Client;
    ClientRegistrationDelete => Management, Client;
    KeyCreate => Management, Key;
    KeyRotate => Management, Key;
    KeyRevoke => Management, Key;
    SettingProtocolUpdate => Management, Setting;
    SettingAuthenticationUpdate => Management, Setting;
    AccountProfileUpdate => Account, User;
    AccountIdentifierUpdate => Account, User;
    AccountPasswordChange => Account, User;
    AccountCredentialReplace => Account, User;
    AccountTotpEnable => Account, User;
    AccountTotpDisable => Account, User;
    AccountRecoveryCodeRegenerate => Account, User;
    AccountPasskeyAdd => Account, Passkey;
    AccountPasskeyUpdate => Account, Passkey;
    AccountPasskeyRemove => Account, Passkey;
    SignIn => SignIn, User;
    AccountLock => SignIn, User;
    SessionReauthenticate => SignIn, Session;
    SessionRevoke => SignIn, Session;
    // A client was signed in to with a session established earlier, without
    // authenticating again.
    SessionReuse => SignIn, Client;
    // A client failed to prove its identity with the credential it presented.
    ClientAuthenticate => SignIn, Client;
    ConsentGrant => Authorization, Client;
    ConsentDeny => Authorization, Client;
    // A refresh token's grant was revoked, with the access tokens issued from it.
    TokenRevoke => Authorization, User;
    // A single access token was revoked; its grant stays usable.
    AccessTokenRevoke => Authorization, User;
    TokenReplay => Authorization, User;
    DeviceApprove => Authorization, DeviceAuthorization;
    DeviceDeny => Authorization, DeviceAuthorization;
    DeviceRevoke => Authorization, DeviceAuthorization;
}

impl AuditAction {
    /// The enable/disable pair for a toggled object.
    #[must_use]
    pub const fn toggle(enabled: bool, enable: Self, disable: Self) -> Self {
        if enabled { enable } else { disable }
    }
}

/// Who performed an action. Labels are display snapshots; when absent the
/// writer snapshots the current name of a user or client actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditActor {
    pub kind: AuditActorKind,
    pub oid: Option<Uuid>,
    pub label: Option<String>,
}

impl AuditActor {
    #[must_use]
    pub const fn user(oid: Uuid) -> Self {
        Self {
            kind: AuditActorKind::User,
            oid: Some(oid),
            label: None,
        }
    }

    #[must_use]
    pub const fn client(oid: Uuid) -> Self {
        Self {
            kind: AuditActorKind::Client,
            oid: Some(oid),
            label: None,
        }
    }

    #[must_use]
    pub const fn system() -> Self {
        Self {
            kind: AuditActorKind::System,
            oid: None,
            label: None,
        }
    }

    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            kind: AuditActorKind::Anonymous,
            oid: None,
            label: None,
        }
    }

    #[must_use]
    pub fn from_principal(principal: &ActorPrincipal) -> Self {
        match principal {
            ActorPrincipal::User { user_oid, .. } => Self::user(Uuid::from(*user_oid)),
            ActorPrincipal::Client { client_oid } => Self::client(*client_oid),
        }
    }
}

/// Request identifiers carried by an explicit actor context.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditCorrelation {
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
}

/// A reference to another object inside recorded changes, such as a group
/// member or an assigned role, with its display snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRef {
    pub kind: AuditTargetKind,
    pub oid: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl AuditRef {
    #[must_use]
    pub fn new(kind: AuditTargetKind, oid: Uuid, label: impl Into<Option<String>>) -> Self {
        Self {
            kind,
            oid,
            label: label.into(),
        }
    }
}

/// Before and after state of one changed attribute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditChangeValue {
    /// A scalar or structured value.
    Value {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new: Option<Value>,
    },
    /// Members added to and removed from a collection.
    Set {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        added: Vec<Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        removed: Vec<Value>,
    },
    /// A secret whose values are never recorded.
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditChange {
    pub field: AuditField,
    #[serde(flatten)]
    pub value: AuditChangeValue,
}

/// Changed attributes of one audited action. Unchanged values are skipped.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditChanges(Vec<AuditChange>);

impl AuditChanges {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `old` → `new` when they differ.
    pub fn diff<T: Serialize + PartialEq + ?Sized>(
        &mut self,
        field: AuditField,
        old: &T,
        new: &T,
    ) -> &mut Self {
        if old != new {
            self.0.push(AuditChange {
                field,
                value: AuditChangeValue::Value {
                    old: to_value(old),
                    new: to_value(new),
                },
            });
        }
        self
    }

    /// Records the initial value of a created object.
    pub fn set<T: Serialize + ?Sized>(&mut self, field: AuditField, new: &T) -> &mut Self {
        let new = to_value(new);
        if new.as_ref().is_some_and(|value| !is_empty(value)) {
            self.0.push(AuditChange {
                field,
                value: AuditChangeValue::Value { old: None, new },
            });
        }
        self
    }

    /// Records the final value of a removed object.
    pub fn unset<T: Serialize + ?Sized>(&mut self, field: AuditField, old: &T) -> &mut Self {
        let old = to_value(old);
        if old.as_ref().is_some_and(|value| !is_empty(value)) {
            self.0.push(AuditChange {
                field,
                value: AuditChangeValue::Value { old, new: None },
            });
        }
        self
    }

    /// Records collection membership changes between `old` and `new`.
    pub fn members<T, I, J>(&mut self, field: AuditField, old: I, new: J) -> &mut Self
    where
        T: Serialize + PartialEq,
        I: IntoIterator<Item = T>,
        J: IntoIterator<Item = T>,
    {
        let old: Vec<T> = old.into_iter().collect();
        let new: Vec<T> = new.into_iter().collect();
        let added: Vec<&T> = new.iter().filter(|item| !old.contains(item)).collect();
        let removed: Vec<&T> = old.iter().filter(|item| !new.contains(item)).collect();
        self.delta(field, &added, &removed)
    }

    /// Records explicitly added and removed members.
    pub fn delta<T: Serialize>(
        &mut self,
        field: AuditField,
        added: &[T],
        removed: &[T],
    ) -> &mut Self {
        let added: Vec<Value> = added.iter().filter_map(to_value).collect();
        let removed: Vec<Value> = removed.iter().filter_map(to_value).collect();
        if !added.is_empty() || !removed.is_empty() {
            self.0.push(AuditChange {
                field,
                value: AuditChangeValue::Set { added, removed },
            });
        }
        self
    }

    /// Records changed translations of a localized object.
    pub fn localized(
        &mut self,
        before: &LocalizedMetadata,
        after: &LocalizedMetadata,
    ) -> &mut Self {
        self.diff(AuditField::Names, &before.names, &after.names)
            .diff(
                AuditField::Descriptions,
                &before.descriptions,
                &after.descriptions,
            )
    }

    /// Records that a secret changed without recording its values.
    pub fn secret(&mut self, field: AuditField) -> &mut Self {
        self.0.push(AuditChange {
            field,
            value: AuditChangeValue::Redacted,
        });
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[AuditChange] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<AuditChange> {
        self.0
    }
}

impl From<Vec<AuditChange>> for AuditChanges {
    fn from(value: Vec<AuditChange>) -> Self {
        Self(value)
    }
}

fn to_value<T: Serialize + ?Sized>(value: &T) -> Option<Value> {
    match serde_json::to_value(value) {
        Ok(Value::Null) | Err(_) => None,
        Ok(value) => Some(value),
    }
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

/// One audit fact to append. Request context (IP address, User-Agent,
/// request and trace identifiers, and the authenticated actor) is captured by
/// the writer; a record only carries what the call site knows.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    pub action: AuditAction,
    pub outcome: AuditOutcome,
    pub failure_reason: Option<AuditFailureReason>,
    pub actor: Option<AuditActor>,
    /// Actor used when neither `actor` nor the request names one.
    pub default_actor: Option<AuditActor>,
    pub correlation: Option<AuditCorrelation>,
    pub target_oid: Option<Uuid>,
    pub target_label: Option<String>,
    pub client_oid: Option<Uuid>,
    pub auth_methods: Vec<AuditAuthMethod>,
    pub changes: AuditChanges,
}

impl AuditRecord {
    #[must_use]
    pub fn success(action: AuditAction, target_oid: impl Into<Option<Uuid>>) -> Self {
        Self {
            action,
            outcome: AuditOutcome::Success,
            failure_reason: None,
            actor: None,
            default_actor: None,
            correlation: None,
            target_oid: target_oid.into(),
            target_label: None,
            client_oid: None,
            auth_methods: Vec::new(),
            changes: AuditChanges::default(),
        }
    }

    #[must_use]
    pub fn failure(
        action: AuditAction,
        reason: AuditFailureReason,
        target_oid: impl Into<Option<Uuid>>,
    ) -> Self {
        Self {
            outcome: AuditOutcome::Failure,
            failure_reason: Some(reason),
            ..Self::success(action, target_oid)
        }
    }

    /// Display snapshot of the target. Required for deletions, whose target
    /// row is gone when the record is written.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.target_label = Some(label.into());
        self
    }

    /// Overrides the request's authenticated actor.
    #[must_use]
    pub fn actor(mut self, actor: AuditActor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// The actor when the request has no authenticated one, such as the
    /// session owner signing out through the sign-in application.
    #[must_use]
    pub fn default_actor(mut self, actor: AuditActor) -> Self {
        self.default_actor = Some(actor);
        self
    }

    /// Uses an explicit actor context, including its request identifiers.
    #[must_use]
    pub fn by(mut self, context: &ActorContext) -> Self {
        self.actor = Some(AuditActor::from_principal(&context.principal));
        self.correlation = Some(AuditCorrelation {
            request_id: Some(context.request_id.as_str().to_owned()),
            trace_id: context.trace_id.as_ref().map(|id| id.as_str().to_owned()),
        });
        self
    }

    /// The OAuth client application through which the action happened.
    #[must_use]
    pub fn client(mut self, client_oid: Uuid) -> Self {
        self.client_oid = Some(client_oid);
        self
    }

    #[must_use]
    pub fn auth_methods(mut self, methods: Vec<AuditAuthMethod>) -> Self {
        self.auth_methods = methods;
        self
    }

    #[must_use]
    pub fn changes(mut self, changes: AuditChanges) -> Self {
        self.changes = changes;
        self
    }

    #[must_use]
    pub fn with_changes(mut self, build: impl FnOnce(&mut AuditChanges)) -> Self {
        build(&mut self.changes);
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn diff_skips_unchanged_values_and_keeps_changed_ones() {
        let mut changes = AuditChanges::new();
        changes.diff(AuditField::Name, "Admins", "Admins").diff(
            AuditField::Description,
            "old",
            "new",
        );
        assert_eq!(
            serde_json::to_value(&changes).unwrap(),
            json!([{ "field": "description", "type": "value", "old": "old", "new": "new" }])
        );
    }

    #[test]
    fn secrets_never_carry_values() {
        let mut changes = AuditChanges::new();
        changes.secret(AuditField::Password);
        assert_eq!(
            serde_json::to_value(&changes).unwrap(),
            json!([{ "field": "password", "type": "redacted" }])
        );
    }

    #[test]
    fn members_record_only_the_difference() {
        let mut changes = AuditChanges::new();
        changes.members(AuditField::Roles, ["a", "b"], ["b", "c"]);
        changes.members(AuditField::Scopes, ["x"], ["x"]);
        assert_eq!(
            serde_json::to_value(&changes).unwrap(),
            json!([{ "field": "roles", "type": "set", "added": ["c"], "removed": ["a"] }])
        );
    }

    #[test]
    fn created_objects_skip_empty_initial_values() {
        let mut changes = AuditChanges::new();
        changes
            .set(AuditField::Name, "Ops")
            .set(AuditField::Description, "")
            .set::<Option<String>>(AuditField::Email, &None);
        assert_eq!(changes.as_slice().len(), 1);
    }

    #[test]
    fn stored_changes_round_trip() {
        let mut changes = AuditChanges::new();
        changes
            .diff(AuditField::Enabled, &true, &false)
            .members(AuditField::Members, [1], [2])
            .secret(AuditField::Totp);
        let stored = serde_json::to_value(&changes).unwrap();
        assert_eq!(
            serde_json::from_value::<AuditChanges>(stored).unwrap(),
            changes
        );
    }

    #[test]
    fn amr_values_map_to_distinct_methods() {
        let methods = AuditAuthMethod::from_amr_values(&["otp", "pwd", "mfa", "pwd"]);
        assert_eq!(
            methods,
            vec![AuditAuthMethod::Password, AuditAuthMethod::Otp]
        );
    }
}
