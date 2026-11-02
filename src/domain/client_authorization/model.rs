use std::{collections::BTreeSet, error::Error, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use uuid::Uuid;

use crate::{
    auth::model::SessionOid,
    authorization::{
        administrator::AdministratorBinding,
        authority::UserPermissionAuthority,
        catalog::{AdministratorRole, ManagementScope},
        ids::{AuthorizationVersion, PolicyVersion},
        snapshot::{ManagementAuthorizationSnapshot, ManagementGrantKind},
    },
    client::model::ClientOid,
    openid_connect::{
        AuthorizationRequestData, ClaimsRequest, CodeChallengeMethod,
        model::authorization_request::AuthorizationRequestParams,
    },
    rbac::RoleAuthorizationSnapshot,
    rbac::{
        BusinessAuthorizationSnapshot,
        ids::{ResourceOid, RoleOid, UserRoleBindingOid},
        snapshot::UserRoleBindingSnapshot,
    },
    user::UserOid,
};

pub use super::device::{
    DeviceAuthorizationApproval, DeviceAuthorizationData, DeviceAuthorizationRequestData,
    DevicePollOutcome, DeviceRequestStatus, DeviceRequestTransitionError,
    SLOW_DOWN_INCREMENT_SECONDS, USER_CODE_ALPHABET, USER_CODE_LENGTH, device_code_digest,
    format_user_code, normalize_user_code,
};

pub type ClientAuthorizationOid = Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ClientAuthorizationType {
    PushedAuthorizationRequest,
    AuthorizationRequest,
    AuthorizationCode,
    AccessToken,
    RefreshToken,
    RegistrationAccessToken,
    DeviceAuthorizationRequest,
    DeviceAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseClientAuthorizationTypeError;

impl fmt::Display for ParseClientAuthorizationTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid client authorization type")
    }
}

impl Error for ParseClientAuthorizationTypeError {}

impl FromStr for ClientAuthorizationType {
    type Err = ParseClientAuthorizationTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == s)
            .ok_or(ParseClientAuthorizationTypeError)
    }
}

/// Explicit access-token principal. A client OID is never stored as a user OID
/// and a machine token never carries a browser session. Legacy records that
/// omit the field deserialize as `User`.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenPrincipal {
    #[default]
    User,
    Client,
}

impl AccessTokenPrincipal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Client => "client",
        }
    }

    #[must_use]
    pub const fn is_human(self) -> bool {
        matches!(self, Self::User)
    }

    #[must_use]
    pub const fn is_machine(self) -> bool {
        matches!(self, Self::Client)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagementGrantKindData {
    /// Historical only; decodable so old records can be inspected but rejected
    /// by every live validation path after the unified-RBAC cutover.
    AdministratorBinding,
    UserRbac,
}

impl From<ManagementGrantKind> for ManagementGrantKindData {
    fn from(value: ManagementGrantKind) -> Self {
        match value {
            ManagementGrantKind::AdministratorBinding => Self::AdministratorBinding,
            ManagementGrantKind::UserRbac => Self::UserRbac,
        }
    }
}

impl From<ManagementGrantKindData> for ManagementGrantKind {
    fn from(value: ManagementGrantKindData) -> Self {
        match value {
            ManagementGrantKindData::AdministratorBinding => Self::AdministratorBinding,
            ManagementGrantKindData::UserRbac => Self::UserRbac,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdministratorRoleData {
    Owner,
    Admin,
    Viewer,
}

impl From<AdministratorRole> for AdministratorRoleData {
    fn from(value: AdministratorRole) -> Self {
        match value {
            AdministratorRole::Owner => Self::Owner,
            AdministratorRole::Admin => Self::Admin,
            AdministratorRole::Viewer => Self::Viewer,
        }
    }
}

impl From<AdministratorRoleData> for AdministratorRole {
    fn from(value: AdministratorRoleData) -> Self {
        match value {
            AdministratorRoleData::Owner => Self::Owner,
            AdministratorRoleData::Admin => Self::Admin,
            AdministratorRoleData::Viewer => Self::Viewer,
        }
    }
}

/// Serializable, non-reusable management authorization snapshot carried by
/// codes and tokens. It mirrors the foundation snapshot without treating role
/// or permission names as identity: for current grant kinds `grant_version`
/// carries the derived grant-authority fingerprint, and
/// `client_policy_version` carries the derived client-authority fingerprint.
/// Neither field is a record optimistic-lock version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagementAuthorizationSnapshotData {
    pub grant_kind: ManagementGrantKindData,
    pub grant_oid: String,
    pub grant_version: Uuid,
    pub policy_version: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<AdministratorRoleData>,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub client_policy_version: Uuid,
}

impl ManagementAuthorizationSnapshotData {
    #[must_use]
    pub fn for_administrator_binding(
        binding: &AdministratorBinding,
        permissions: impl IntoIterator<Item = ManagementScope>,
        policy_version: PolicyVersion,
        client_policy_version: PolicyVersion,
    ) -> Self {
        let mut permissions = permissions
            .into_iter()
            .map(|scope| scope.name().to_owned())
            .collect::<Vec<_>>();
        permissions.sort_unstable();
        Self {
            grant_kind: ManagementGrantKindData::AdministratorBinding,
            grant_oid: binding.oid.0.to_string(),
            grant_version: binding.version.as_uuid(),
            policy_version: policy_version.as_uuid(),
            role: Some(binding.role.into()),
            permissions,
            client_policy_version: client_policy_version.as_uuid(),
        }
    }

    /// Current human snapshot: user OID identity, whole-user authorization
    /// generation and the exact effective permission set. No role name is
    /// carried.
    #[must_use]
    pub fn for_user_permission_authority(
        authority: &UserPermissionAuthority,
        policy_version: PolicyVersion,
        client_policy_version: PolicyVersion,
    ) -> Self {
        let mut permissions = authority
            .permissions
            .iter()
            .map(|scope| scope.name().to_owned())
            .collect::<Vec<_>>();
        permissions.sort_unstable();
        Self {
            grant_kind: ManagementGrantKindData::UserRbac,
            grant_oid: authority.user_oid.0.to_string(),
            grant_version: authority.version.as_uuid(),
            policy_version: policy_version.as_uuid(),
            role: None,
            permissions,
            client_policy_version: client_policy_version.as_uuid(),
        }
    }

    /// Exact conversion back to the foundation snapshot. Unknown reserved or
    /// non-management permission names are rejected, never silently dropped.
    pub fn to_snapshot(
        &self,
    ) -> Result<ManagementAuthorizationSnapshot, ManagementSnapshotDataError> {
        let grant_oid = Uuid::parse_str(&self.grant_oid)
            .map_err(|_| ManagementSnapshotDataError::InvalidGrantOid)?;
        let mut permissions = std::collections::BTreeSet::new();
        for name in &self.permissions {
            let scope = ManagementScope::parse(name)
                .map_err(|_| ManagementSnapshotDataError::InvalidPermission(name.clone()))?;
            if !permissions.insert(scope) {
                return Err(ManagementSnapshotDataError::DuplicatePermission(
                    name.clone(),
                ));
            }
        }
        let role = self.role.map(AdministratorRole::from);
        if self.grant_kind == ManagementGrantKindData::AdministratorBinding && role.is_none() {
            return Err(ManagementSnapshotDataError::MissingRole);
        }
        if matches!(self.grant_kind, ManagementGrantKindData::UserRbac) && role.is_some() {
            return Err(ManagementSnapshotDataError::UnexpectedRole);
        }
        Ok(ManagementAuthorizationSnapshot {
            grant_kind: self.grant_kind.into(),
            grant_oid,
            grant_fingerprint: AuthorizationVersion::from_uuid(self.grant_version),
            policy_version: PolicyVersion::from_uuid(self.policy_version),
            role,
            permissions,
        })
    }

    #[must_use]
    pub fn management_scopes(&self) -> BTreeSet<ManagementScope> {
        self.permissions
            .iter()
            .filter_map(|name| ManagementScope::from_name(name))
            .collect()
    }

    #[must_use]
    pub fn has_permission(&self, scope: ManagementScope) -> bool {
        self.permissions.iter().any(|name| name == scope.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagementSnapshotDataError {
    #[error("management snapshot grant OID is invalid")]
    InvalidGrantOid,
    #[error("management snapshot permission is not a trusted catalog scope: {0}")]
    InvalidPermission(String),
    #[error("management snapshot contains a duplicate permission: {0}")]
    DuplicatePermission(String),
    #[error("an administrator snapshot must carry its role")]
    MissingRole,
    #[error("a client management snapshot must not carry a human role")]
    UnexpectedRole,
}

/// Serializable business RBAC binding source. The binding OID is the grant
/// identity and the role OID is the referenced role identity; neither name nor
/// optimistic-lock version is authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusinessBindingSnapshotData {
    pub binding_oid: String,
    pub role_oid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusinessRoleSnapshotData {
    pub role_oid: String,
}

/// Serializable, non-reusable business authorization snapshot carried by
/// codes, access tokens and refresh tokens.
///
/// `user_oid`/`user_authorization_version` are absent on an explicit machine
/// grant; the machine path never fabricates a user, binding or role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusinessAuthorizationSnapshotData {
    pub resource_oid: String,
    pub resource_uri: String,
    /// API resource authorization policy version; independent of the user
    /// authority fingerprint.
    pub policy_version: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_oid: Option<String>,
    /// Opaque derived whole-user authority fingerprint, not a record
    /// optimistic-lock version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authorization_version: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<BusinessBindingSnapshotData>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<BusinessRoleSnapshotData>,
}

impl BusinessAuthorizationSnapshotData {
    #[must_use]
    pub fn from_snapshot(snapshot: &BusinessAuthorizationSnapshot) -> Self {
        let mut bindings = snapshot
            .bindings
            .iter()
            .map(|binding| BusinessBindingSnapshotData {
                binding_oid: binding.binding_oid.0.to_string(),
                role_oid: binding.role_oid.0.to_string(),
            })
            .collect::<Vec<_>>();
        bindings.sort_by(|left, right| left.binding_oid.cmp(&right.binding_oid));
        let mut roles = snapshot
            .roles
            .iter()
            .map(|role| BusinessRoleSnapshotData {
                role_oid: role.role_oid.0.to_string(),
            })
            .collect::<Vec<_>>();
        roles.sort_by(|left, right| left.role_oid.cmp(&right.role_oid));
        Self {
            resource_oid: snapshot.resource_oid.0.to_string(),
            resource_uri: snapshot.resource_uri.clone(),
            policy_version: snapshot.policy_version.as_uuid(),
            user_oid: snapshot.user_oid.map(|user| user.0.to_string()),
            user_authorization_version: snapshot
                .user_authorization_version
                .map(|version| version.as_uuid()),
            bindings,
            roles,
        }
    }

    /// Exact conversion back to the foundation snapshot. Invalid UUIDs,
    /// duplicate identities are rejected rather than silently
    /// repaired.
    pub fn to_snapshot(&self) -> Result<BusinessAuthorizationSnapshot, BusinessSnapshotDataError> {
        let resource_oid = ResourceOid(
            Uuid::parse_str(&self.resource_oid)
                .map_err(|_| BusinessSnapshotDataError::InvalidResourceOid)?,
        );
        let policy_version = AuthorizationVersion::from_uuid(self.policy_version);
        let user_oid = self
            .user_oid
            .as_deref()
            .map(|value| {
                Uuid::parse_str(value)
                    .map(UserOid)
                    .map_err(|_| BusinessSnapshotDataError::InvalidUserOid)
            })
            .transpose()?;
        let user_authorization_version = match (user_oid, self.user_authorization_version) {
            (Some(_), Some(version)) => Some(AuthorizationVersion::from_uuid(version)),
            (Some(_), None) => return Err(BusinessSnapshotDataError::MissingUserVersion),
            (None, Some(_)) => return Err(BusinessSnapshotDataError::UnexpectedUserVersion),
            (None, None) => None,
        };

        let mut binding_oids = std::collections::BTreeSet::new();
        let mut bindings = Vec::with_capacity(self.bindings.len());
        for binding in &self.bindings {
            let binding_oid = UserRoleBindingOid(
                Uuid::parse_str(&binding.binding_oid)
                    .map_err(|_| BusinessSnapshotDataError::InvalidBindingOid)?,
            );
            if !binding_oids.insert(binding_oid) {
                return Err(BusinessSnapshotDataError::DuplicateBinding(
                    binding.binding_oid.clone(),
                ));
            }
            let role_oid = RoleOid(
                Uuid::parse_str(&binding.role_oid)
                    .map_err(|_| BusinessSnapshotDataError::InvalidRoleOid)?,
            );
            bindings.push(UserRoleBindingSnapshot {
                binding_oid,
                role_oid,
            });
        }

        let mut role_oids = std::collections::BTreeSet::new();
        let mut roles = Vec::with_capacity(self.roles.len());
        for role in &self.roles {
            let role_oid = RoleOid(
                Uuid::parse_str(&role.role_oid)
                    .map_err(|_| BusinessSnapshotDataError::InvalidRoleOid)?,
            );
            if !role_oids.insert(role_oid) {
                return Err(BusinessSnapshotDataError::DuplicateRole(
                    role.role_oid.clone(),
                ));
            }
            roles.push(RoleAuthorizationSnapshot { role_oid });
        }

        Ok(BusinessAuthorizationSnapshot {
            resource_oid,
            resource_uri: self.resource_uri.clone(),
            policy_version,
            user_oid,
            user_authorization_version,
            bindings,
            roles,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BusinessSnapshotDataError {
    #[error("business snapshot resource OID is invalid")]
    InvalidResourceOid,
    #[error("business snapshot user OID is invalid")]
    InvalidUserOid,
    #[error("business snapshot binding OID is invalid")]
    InvalidBindingOid,
    #[error("business snapshot role OID is invalid")]
    InvalidRoleOid,
    #[error("business snapshot user is missing its authorization version")]
    MissingUserVersion,
    #[error("business snapshot machine grant must not carry a user version")]
    UnexpectedUserVersion,
    #[error("business snapshot contains a duplicate binding: {0}")]
    DuplicateBinding(String),
    #[error("business snapshot contains a duplicate role: {0}")]
    DuplicateRole(String),
}

/// Issuance authorization carried by a code/token. Exactly one variant is
/// present: an instance-management grant or a business RBAC grant. The two are
/// never combined into one credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AuthorizationSnapshotData {
    Business(BusinessAuthorizationSnapshotData),
    Management(ManagementAuthorizationSnapshotData),
}

impl AuthorizationSnapshotData {
    #[must_use]
    pub fn as_management(&self) -> Option<&ManagementAuthorizationSnapshotData> {
        match self {
            Self::Management(snapshot) => Some(snapshot),
            Self::Business(_) => None,
        }
    }

    #[must_use]
    pub fn as_business(&self) -> Option<&BusinessAuthorizationSnapshotData> {
        match self {
            Self::Business(snapshot) => Some(snapshot),
            Self::Management(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCodeData {
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub user_oid: String,
    pub session_oid: SessionOid,
    #[serde(default)]
    pub protected_session_id: Option<String>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub redirect_uri: String,
    #[serde(default = "default_redirect_uri_was_supplied")]
    pub redirect_uri_was_supplied: bool,
    pub auth_time: Option<i64>,
    pub claims: Option<ClaimsRequest>,
    /// Issuance authorization clipped at approval: exactly one management or
    /// business RBAC snapshot. Legacy codes omit it and keep their previous
    /// self-service behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<AuthorizationSnapshotData>,
}

fn default_redirect_uri_was_supplied() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenData {
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    pub user_oid: String,
    /// Browser session the token was issued from; `None` for device issued
    /// tokens, which are bound to a device authorization relation instead.
    #[serde(default)]
    pub session_oid: Option<SessionOid>,
    #[serde(default)]
    pub protected_session_id: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub rotated_from: Option<String>,
    #[serde(default)]
    pub authorization_code_oid: Option<String>,
    /// Device authorization relation this token belongs to, when the token was
    /// not issued from a browser session.
    #[serde(default)]
    pub device_authorization_oid: Option<String>,
    /// Bound to the authentication mode used when this token was issued.
    /// Legacy records omit this field.
    #[serde(default)]
    pub client_authentication_mode: Option<ClientAuthenticationMode>,
    /// A business RBAC snapshot is preserved unchanged across rotation. A
    /// management snapshot is never carried into a refresh token in this
    /// release; the field exists so an attempt to persist one can be rejected
    /// and so legacy records deserialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<AuthorizationSnapshotData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessTokenData {
    pub scope: String,
    /// Actual API resource targets selected for this token. This is a real
    /// issuance fact (the same selection used for the JWT audience), not a
    /// record version or client identity. A client-ID audience is never
    /// fabricated into a resource; an empty list means OAuth resource omission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    /// User subject for a human token; `None` for a machine token. A client OID
    /// is never stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_oid: Option<String>,
    /// Explicit principal kind. Legacy records without this field are human.
    #[serde(default)]
    pub principal: AccessTokenPrincipal,
    /// Browser session the token was issued from. `None` for machine tokens and
    /// for tokens issued from a device authorization relation, which is
    /// independent of the browser session that approved it (ADR 0004).
    #[serde(default)]
    pub session_oid: Option<SessionOid>,
    #[serde(default)]
    pub protected_session_id: Option<String>,
    pub authorization_code_oid: Option<String>,
    #[serde(default)]
    pub refresh_token_oid: Option<String>,
    /// Device authorization relation the token was issued from, when the
    /// token was not issued from a browser session.
    #[serde(default)]
    pub device_authorization_oid: Option<String>,
    #[serde(default)]
    pub client_authentication_mode: Option<ClientAuthenticationMode>,
    /// Issuance authorization snapshot carried by the token. Absent for pure
    /// self-service and ordinary legacy machine access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<AuthorizationSnapshotData>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthenticationMode {
    Public,
    Confidential,
}

impl ClientAuthenticationMode {
    #[must_use]
    pub const fn from_credentials(has_credentials: bool) -> Self {
        if has_credentials {
            Self::Confidential
        } else {
            Self::Public
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationAccessTokenData {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAuthorizationRequest {
    pub request: AuthorizationRequestData,
    #[serde(default)]
    pub interaction: AuthorizationInteractionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationRequestData {
    pub request_uri_digest: String,
    pub parameters: AuthorizationRequestParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthorizationData {
    PushedAuthorizationRequest(PushedAuthorizationRequestData),
    AuthorizationRequest(StoredAuthorizationRequest),
    AuthorizationCode(AuthorizationCodeData),
    AccessToken(AccessTokenData),
    RefreshToken(RefreshTokenData),
    RegistrationAccessToken(RegistrationAccessTokenData),
    DeviceAuthorizationRequest(DeviceAuthorizationRequestData),
    DeviceAuthorization(DeviceAuthorizationData),
}

impl ClientAuthorizationData {
    #[must_use]
    pub const fn authorization_type(&self) -> ClientAuthorizationType {
        match self {
            Self::PushedAuthorizationRequest(_) => {
                ClientAuthorizationType::PushedAuthorizationRequest
            }
            Self::AuthorizationRequest(_) => ClientAuthorizationType::AuthorizationRequest,
            Self::AuthorizationCode(_) => ClientAuthorizationType::AuthorizationCode,
            Self::AccessToken(_) => ClientAuthorizationType::AccessToken,
            Self::RefreshToken(_) => ClientAuthorizationType::RefreshToken,
            Self::RegistrationAccessToken(_) => ClientAuthorizationType::RegistrationAccessToken,
            Self::DeviceAuthorizationRequest(_) => {
                ClientAuthorizationType::DeviceAuthorizationRequest
            }
            Self::DeviceAuthorization(_) => ClientAuthorizationType::DeviceAuthorization,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthorizationInteractionState {
    pub selected_session_oid: Option<SessionOid>,
    #[serde(default)]
    pub selected_protected_session_id: Option<String>,
    pub selected_user_oid: Option<String>,
    pub selection_source: Option<SelectionSource>,
    #[serde(default)]
    pub consent_state: ConsentState,
    pub consent_decided_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SelectionSource {
    Auto,
    AccountPicker,
    FreshLogin,
    Reauthentication,
}

impl SelectionSource {
    /// Prevents a weaker interaction from replacing a completed login selection.
    pub fn can_replace(self, current: Option<Self>) -> bool {
        match current {
            Some(Self::Reauthentication) => self == Self::Reauthentication,
            Some(Self::FreshLogin) => self != Self::AccountPicker,
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ConsentState {
    #[default]
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
pub struct ClientAuthorization {
    pub oid: ClientAuthorizationOid,
    pub client_oid: ClientOid,
    pub type_: ClientAuthorizationType,
    pub data: ClientAuthorizationData,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::SelectionSource::{AccountPicker, Auto, FreshLogin, Reauthentication};

    #[test]
    fn legacy_access_tokens_default_to_a_human_principal_and_no_management() {
        let legacy = serde_json::json!({
            "scope": "openid account.read",
            "user_oid": "11111111-1111-1111-1111-111111111111",
            "authorization_code_oid": null
        });
        let data: super::AccessTokenData = serde_json::from_value(legacy).unwrap();
        assert_eq!(data.principal, super::AccessTokenPrincipal::User);
        assert_eq!(
            data.user_oid.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(data.management.is_none());
    }

    #[test]
    fn machine_access_tokens_carry_no_user_or_session() {
        let data = super::AccessTokenData {
            scope: "management.audit.read".to_owned(),
            resources: Vec::new(),
            user_oid: None,
            principal: super::AccessTokenPrincipal::Client,
            session_oid: None,
            protected_session_id: None,
            authorization_code_oid: None,
            refresh_token_oid: None,
            device_authorization_oid: None,
            client_authentication_mode: None,
            management: None,
        };
        assert!(data.principal.is_machine());
        assert!(data.user_oid.is_none());
        assert!(data.session_oid.is_none());
    }

    #[test]
    fn authorization_snapshot_data_preserves_management_and_business_wire_shapes() {
        let management = super::ManagementAuthorizationSnapshotData {
            grant_kind: super::ManagementGrantKindData::UserRbac,
            grant_oid: "11111111-1111-1111-1111-111111111111".to_owned(),
            grant_version: uuid::Uuid::new_v4(),
            policy_version: uuid::Uuid::new_v4(),
            role: None,
            permissions: vec!["management.user.read".to_owned()],
            client_policy_version: uuid::Uuid::new_v4(),
        };
        let management_wrapped = super::AuthorizationSnapshotData::Management(management.clone());
        assert_eq!(
            serde_json::to_value(&management_wrapped).unwrap(),
            serde_json::to_value(&management).unwrap()
        );
        assert!(
            serde_json::to_value(&management_wrapped)
                .unwrap()
                .get("rbac")
                .is_none()
        );

        let business = super::BusinessAuthorizationSnapshotData {
            resource_oid: "22222222-2222-2222-2222-222222222222".to_owned(),
            resource_uri: "https://api.example.test".to_owned(),
            policy_version: uuid::Uuid::new_v4(),
            user_oid: None,
            user_authorization_version: None,
            bindings: Vec::new(),
            roles: Vec::new(),
        };
        let business_wrapped = super::AuthorizationSnapshotData::Business(business.clone());
        let encoded = serde_json::to_value(&business_wrapped).unwrap();
        assert_eq!(encoded, serde_json::to_value(&business).unwrap());
        assert_eq!(
            serde_json::from_value::<super::AuthorizationSnapshotData>(encoded).unwrap(),
            super::AuthorizationSnapshotData::Business(business)
        );
    }

    #[test]
    fn business_snapshot_nested_identities_do_not_carry_record_versions() {
        let authority_fingerprint = uuid::Uuid::new_v4();
        let data = super::BusinessAuthorizationSnapshotData {
            resource_oid: "22222222-2222-2222-2222-222222222222".to_owned(),
            resource_uri: "https://api.example.test".to_owned(),
            policy_version: uuid::Uuid::new_v4(),
            user_oid: Some("11111111-1111-1111-1111-111111111111".to_owned()),
            user_authorization_version: Some(authority_fingerprint),
            bindings: vec![super::BusinessBindingSnapshotData {
                binding_oid: "33333333-3333-3333-3333-333333333333".to_owned(),
                role_oid: "44444444-4444-4444-4444-444444444444".to_owned(),
            }],
            roles: vec![super::BusinessRoleSnapshotData {
                role_oid: "44444444-4444-4444-4444-444444444444".to_owned(),
            }],
        };

        let snapshot = data.to_snapshot().unwrap();
        assert_eq!(
            super::BusinessAuthorizationSnapshotData::from_snapshot(&snapshot),
            data
        );

        let encoded = serde_json::to_value(&data).unwrap();
        assert!(encoded["bindings"][0].get("version").is_none());
        assert!(encoded["roles"][0].get("version").is_none());
        assert_eq!(
            encoded["user_authorization_version"],
            serde_json::json!(authority_fingerprint)
        );
    }

    #[test]
    fn snapshot_data_round_trips_and_rejects_unknown_permissions() {
        use crate::authorization::{
            AuthorizationVersion, ManagementScope, PolicyVersion, UserPermissionAuthority,
        };
        let authority = UserPermissionAuthority::new(
            crate::user::UserOid(uuid::Uuid::new_v4()),
            AuthorizationVersion::fresh(),
            [ManagementScope::UsersRead, ManagementScope::AuditRead],
        );
        let policy = PolicyVersion::new();
        let client_policy = PolicyVersion::new();
        let data = super::ManagementAuthorizationSnapshotData::for_user_permission_authority(
            &authority,
            policy,
            client_policy,
        );
        let snapshot = data.to_snapshot().unwrap();
        assert_eq!(snapshot.grant_oid, authority.user_oid.0);
        assert_eq!(snapshot.permissions.len(), 2);
        assert_eq!(data.client_policy_version, client_policy.as_uuid());
        let mut invalid = data.clone();
        invalid.permissions.push("management.unknown".to_owned());
        assert!(invalid.to_snapshot().is_err());
        let mut invalid = data;
        invalid.permissions.push("orders.read".to_owned());
        assert!(invalid.to_snapshot().is_err());
    }

    #[test]
    fn user_rbac_snapshot_uses_stable_kind_and_user_oid_identity() {
        use crate::authorization::{
            authority::UserPermissionAuthority,
            catalog::ManagementScope,
            ids::{AuthorizationVersion, PolicyVersion},
        };
        use uuid::Uuid;

        let user = crate::user::UserOid(uuid::Uuid::new_v4());
        let grant_version = AuthorizationVersion::new();
        let authority = UserPermissionAuthority::new(
            user,
            grant_version,
            [ManagementScope::UsersRead, ManagementScope::GroupsWrite],
        );
        let client_policy = PolicyVersion::new();
        let data = super::ManagementAuthorizationSnapshotData::for_user_permission_authority(
            &authority,
            PolicyVersion::new(),
            client_policy,
        );
        assert_eq!(data.grant_kind, super::ManagementGrantKindData::UserRbac);
        assert_eq!(data.grant_oid, user.0.to_string());
        assert_eq!(data.grant_version, grant_version.as_uuid());
        assert_eq!(data.role, None);
        assert_eq!(data.client_policy_version, client_policy.as_uuid());

        let encoded = serde_json::to_value(&data).unwrap();
        assert_eq!(encoded["grant_kind"], serde_json::json!("user_rbac"));
        let snapshot = data.to_snapshot().unwrap();
        assert_eq!(snapshot.permissions.len(), 2);
        assert_eq!(
            snapshot.grant_kind,
            crate::authorization::snapshot::ManagementGrantKind::UserRbac
        );
    }

    #[test]
    fn selection_transitions_preserve_stronger_authentication() {
        let incoming = [Auto, AccountPicker, FreshLogin, Reauthentication];
        for (current, expected) in [
            (None, [true, true, true, true]),
            (Some(Auto), [true, true, true, true]),
            (Some(AccountPicker), [true, true, true, true]),
            (Some(FreshLogin), [true, false, true, true]),
            (Some(Reauthentication), [false, false, false, true]),
        ] {
            for (next, allowed) in incoming.into_iter().zip(expected) {
                assert_eq!(
                    next.can_replace(current),
                    allowed,
                    "{current:?} -> {next:?}"
                );
            }
        }
    }
}
