//! Trusted management authorization catalog.
//!
//! This module is the single source of truth for the built-in management
//! scopes. It is deliberately compiled into the service and never derived from
//! database rows, user metadata, translations or console labels.
//!
//! Lookups are exact-match only. A name that merely starts with the reserved
//! `management.` prefix is never treated as a known scope, and ownership of one
//! scope never grants another scope.

use std::fmt;

use crate::{authorization::ids::PolicyVersion, rbac::deterministic_oid};

pub const MANAGEMENT_SCOPE_PREFIX: &str = "management.";
pub const MANAGEMENT_SCOPE_COUNT: usize = <ManagementScope as strum::EnumCount>::COUNT;

/// Fixed instance administrator roles. The role names are not OAuth scopes and
/// business roles with the same key never confer these capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdministratorRole {
    Owner,
    Admin,
    Viewer,
}

impl AdministratorRole {
    pub const ALL: [Self; 3] = [Self::Owner, Self::Admin, Self::Viewer];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown administrator role")]
pub struct ParseAdministratorRoleError;

impl std::str::FromStr for AdministratorRole {
    type Err = ParseAdministratorRoleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "viewer" => Ok(Self::Viewer),
            _ => Err(ParseAdministratorRoleError),
        }
    }
}

impl fmt::Display for AdministratorRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Explicit role eligibility recorded for one catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementRoleEligibility {
    viewer: bool,
    admin: bool,
    owner: bool,
}

impl ManagementRoleEligibility {
    /// `V` scopes: explicitly held by viewer, admin and owner.
    pub const VIEWER: Self = Self {
        viewer: true,
        admin: true,
        owner: true,
    };

    /// `A` scopes: explicitly held by admin and owner.
    pub const ADMIN: Self = Self {
        viewer: false,
        admin: true,
        owner: true,
    };

    /// `O` scopes: explicitly held by owner only.
    pub const OWNER: Self = Self {
        viewer: false,
        admin: false,
        owner: true,
    };

    #[must_use]
    pub const fn allows(self, role: AdministratorRole) -> bool {
        match role {
            AdministratorRole::Owner => self.owner,
            AdministratorRole::Admin => self.admin,
            AdministratorRole::Viewer => self.viewer,
        }
    }

    /// Used by catalog coverage checks. Owner is enumerated on every entry.
    #[must_use]
    pub const fn is_owner_eligible(self) -> bool {
        self.owner
    }
}

/// Required human authentication. Machine principals never claim either human
/// level, and M2M flows are limited separately by [`ManagementFlowAllowance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HumanAuthenticationRequirement {
    None,
    Aal2,
    RecentAal2,
}

impl HumanAuthenticationRequirement {
    #[must_use]
    pub const fn requires_aal2(self) -> bool {
        matches!(self, Self::Aal2 | Self::RecentAal2)
    }

    #[must_use]
    pub const fn requires_recent_aal2(self) -> bool {
        matches!(self, Self::RecentAal2)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aal2 => "aal2",
            Self::RecentAal2 => "recent_aal2",
        }
    }
}

impl fmt::Display for HumanAuthenticationRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Supported principal/flow combinations for a management scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementFlowAllowance {
    pub user_authorization_code: bool,
    pub confidential_client_credentials: bool,
}

impl ManagementFlowAllowance {
    pub const USER_ONLY: Self = Self {
        user_authorization_code: true,
        confidential_client_credentials: false,
    };

    pub const USER_AND_CLIENT_CREDENTIALS: Self = Self {
        user_authorization_code: true,
        confidential_client_credentials: true,
    };
}

/// One trusted catalog entry. `reserved` is always true for the built-in set;
/// the field is explicit so seeds and migrations cannot accidentally treat a
/// management scope as an editable custom scope.
#[derive(Debug, Clone, Copy)]
pub struct ManagementScopeDefinition {
    pub scope: ManagementScope,
    pub name: &'static str,
    pub action: &'static str,
    pub description: &'static str,
    pub roles: ManagementRoleEligibility,
    pub human_authentication: HumanAuthenticationRequirement,
    pub flows: ManagementFlowAllowance,
    pub reserved: bool,
}

impl ManagementScopeDefinition {
    #[must_use]
    pub const fn m2m_allowed(&self) -> bool {
        self.flows.confidential_client_credentials
    }

    #[must_use]
    pub const fn allows_role(&self, role: AdministratorRole) -> bool {
        self.roles.allows(role)
    }
}

/// The 43 trusted management scopes.
///
/// Adding a variant requires a catalog entry, migration seed, error/translation
/// review and explicit role/M2M review. There is no future-scope wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::EnumCount)]
pub enum ManagementScope {
    UsersRead,
    UsersCreate,
    UsersUpdate,
    UsersState,
    UsersRevokeAccess,
    SessionsRead,
    SessionsRevoke,
    CredentialsRead,
    CredentialsRevoke,
    CredentialsReset,
    ClientsRead,
    ClientsCreate,
    ClientsUpdate,
    ClientsState,
    ClientsScopes,
    ClientCredentialsRead,
    ClientCredentialsCreate,
    ClientCredentialsRotate,
    ClientCredentialsRevoke,
    ResourcesRead,
    ResourcesWrite,
    ScopesRead,
    ScopesWrite,
    AdministratorsRead,
    AdministratorsWrite,
    ClientGrantsRead,
    ClientGrantsWrite,
    SettingsRead,
    SettingsWrite,
    AuditRead,
    PermissionRead,
    PermissionWrite,
    RolesRead,
    RolesWrite,
    RoleAssignmentsRead,
    RoleAssignmentsWrite,
    GroupsRead,
    GroupsWrite,
    GroupMembershipsRead,
    GroupMembershipsWrite,
    GroupRolesRead,
    GroupRolesWrite,
    PermissionDelegate,
}

impl ManagementScope {
    pub const ALL: [Self; MANAGEMENT_SCOPE_COUNT] = [
        Self::UsersRead,
        Self::UsersCreate,
        Self::UsersUpdate,
        Self::UsersState,
        Self::UsersRevokeAccess,
        Self::SessionsRead,
        Self::SessionsRevoke,
        Self::CredentialsRead,
        Self::CredentialsRevoke,
        Self::CredentialsReset,
        Self::ClientsRead,
        Self::ClientsCreate,
        Self::ClientsUpdate,
        Self::ClientsState,
        Self::ClientsScopes,
        Self::ClientCredentialsRead,
        Self::ClientCredentialsCreate,
        Self::ClientCredentialsRotate,
        Self::ClientCredentialsRevoke,
        Self::ResourcesRead,
        Self::ResourcesWrite,
        Self::ScopesRead,
        Self::ScopesWrite,
        Self::AdministratorsRead,
        Self::AdministratorsWrite,
        Self::ClientGrantsRead,
        Self::ClientGrantsWrite,
        Self::SettingsRead,
        Self::SettingsWrite,
        Self::AuditRead,
        Self::PermissionRead,
        Self::PermissionWrite,
        Self::RolesRead,
        Self::RolesWrite,
        Self::RoleAssignmentsRead,
        Self::RoleAssignmentsWrite,
        Self::GroupsRead,
        Self::GroupsWrite,
        Self::GroupMembershipsRead,
        Self::GroupMembershipsWrite,
        Self::GroupRolesRead,
        Self::GroupRolesWrite,
        Self::PermissionDelegate,
    ];

    #[must_use]
    pub fn definition(self) -> &'static ManagementScopeDefinition {
        MANAGEMENT_SCOPES
            .iter()
            .find(|definition| definition.scope == self)
            .expect("trusted catalog covers every ManagementScope variant")
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        self.definition().name
    }

    #[must_use]
    pub fn action(self) -> &'static str {
        self.definition().action
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        self.definition().description
    }

    #[must_use]
    pub fn human_authentication(self) -> HumanAuthenticationRequirement {
        self.definition().human_authentication
    }

    #[must_use]
    pub fn allows_role(self, role: AdministratorRole) -> bool {
        self.definition().allows_role(role)
    }

    #[must_use]
    pub fn m2m_allowed(self) -> bool {
        self.definition().m2m_allowed()
    }

    /// Exact catalog lookup. `management.users` and
    /// `management.user.read.extra` are both unknown.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        MANAGEMENT_SCOPES
            .iter()
            .find(|definition| definition.name == name)
            .map(|definition| definition.scope)
    }

    /// Exact catalog lookup with a diagnostic error for names that use the
    /// reserved prefix but are not trusted entries.
    pub fn parse(name: &str) -> Result<Self, ManagementScopeError> {
        if let Some(scope) = Self::from_name(name) {
            return Ok(scope);
        }
        if is_reserved_management_name(name) {
            Err(ManagementScopeError::ReservedPrefix)
        } else {
            Err(ManagementScopeError::Unknown)
        }
    }

    /// Whether this scope can change an owner's security boundary. These
    /// actions additionally require a recent-AAL2 human owner actor.
    #[must_use]
    pub const fn is_owner_target_sensitive(self) -> bool {
        matches!(
            self,
            Self::UsersUpdate
                | Self::UsersState
                | Self::UsersRevokeAccess
                | Self::CredentialsRevoke
                | Self::CredentialsReset
                | Self::AdministratorsWrite
        )
    }

    /// Scopes that first-party machine clients must never receive.
    #[must_use]
    pub fn is_human_only(self) -> bool {
        HUMAN_ONLY_SCOPES.contains(&self)
    }
}

impl fmt::Display for ManagementScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementScopeError {
    #[error("unknown management scope")]
    Unknown,
    #[error("name uses the reserved management prefix but is not in the trusted catalog")]
    ReservedPrefix,
}

/// Reserved-prefix check used by validators, seeds and write paths. This is a
/// name-boundary operation, never an authorization grant.
#[must_use]
pub fn is_reserved_management_name(name: &str) -> bool {
    name.strip_prefix(MANAGEMENT_SCOPE_PREFIX).is_some()
}

#[must_use]
pub fn is_management_scope_name(name: &str) -> bool {
    ManagementScope::from_name(name).is_some()
}

const fn entry(
    scope: ManagementScope,
    name: &'static str,
    action: &'static str,
    description: &'static str,
    roles: ManagementRoleEligibility,
    human_authentication: HumanAuthenticationRequirement,
    flows: ManagementFlowAllowance,
) -> ManagementScopeDefinition {
    ManagementScopeDefinition {
        scope,
        name,
        action,
        description,
        roles,
        human_authentication,
        flows,
        reserved: true,
    }
}

/// Explicit catalog. Owner eligibility is enumerated on every single entry.
pub const MANAGEMENT_SCOPES: [ManagementScopeDefinition; MANAGEMENT_SCOPE_COUNT] = [
    entry(
        ManagementScope::UsersRead,
        "management.user.read",
        "user.read",
        "Read users and user management details",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::UsersCreate,
        "management.user.create",
        "user.create",
        "Create users",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::UsersUpdate,
        "management.user.update",
        "user.update",
        "Update user profiles and identifiers",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::UsersState,
        "management.user.state",
        "user.state",
        "Enable, disable, or unlock users",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::UsersRevokeAccess,
        "management.user.revoke_access",
        "user.revoke_access",
        "Revoke a user's sessions and other access",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::SessionsRead,
        "management.session.read",
        "session.read",
        "Read sessions across users",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::SessionsRevoke,
        "management.session.revoke",
        "session.revoke",
        "Revoke sessions across users",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::CredentialsRead,
        "management.credential.read",
        "credential.read",
        "Read credential and passkey metadata",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::CredentialsRevoke,
        "management.credential.revoke",
        "credential.revoke",
        "Revoke another user's credential",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::CredentialsReset,
        "management.credential.reset",
        "credential.reset",
        "Reset another user's MFA",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::ClientsRead,
        "management.client.read",
        "client.read",
        "Read OAuth client configuration",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ClientsCreate,
        "management.client.create",
        "client.create",
        "Create OAuth clients",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ClientsUpdate,
        "management.client.update",
        "client.update",
        "Update OAuth client configuration",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ClientsState,
        "management.client.state",
        "client.state",
        "Enable or disable OAuth clients",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ClientsScopes,
        "management.client.scope",
        "client.scope",
        "Assign non-reserved scopes to OAuth clients",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ClientCredentialsRead,
        "management.client_credential.read",
        "client_credential.read",
        "Read client credential metadata",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ClientCredentialsCreate,
        "management.client_credential.create",
        "client_credential.create",
        "Create client credentials",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::ClientCredentialsRotate,
        "management.client_credential.rotate",
        "client_credential.rotate",
        "Rotate client credentials",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::ClientCredentialsRevoke,
        "management.client_credential.revoke",
        "client_credential.revoke",
        "Revoke client credentials",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::ResourcesRead,
        "management.resource.read",
        "resource.read",
        "Read API resources",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ResourcesWrite,
        "management.resource.write",
        "resource.write",
        "Create, update, enable, or disable API resources",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ScopesRead,
        "management.scope.read",
        "scope.read",
        "Read the scope catalog",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::ScopesWrite,
        "management.scope.write",
        "scope.write",
        "Create or update non-reserved scopes",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::AdministratorsRead,
        "management.administrator.read",
        "administrator.read",
        "Read administrator bindings",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::AdministratorsWrite,
        "management.administrator.write",
        "administrator.write",
        "Assign or change administrator bindings",
        ManagementRoleEligibility::OWNER,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::ClientGrantsRead,
        "management.client_grant.read",
        "client_grant.read",
        "Read client management grants",
        ManagementRoleEligibility::OWNER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::ClientGrantsWrite,
        "management.client_grant.write",
        "client_grant.write",
        "Set or revoke client management grants",
        ManagementRoleEligibility::OWNER,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::SettingsRead,
        "management.setting.read",
        "setting.read",
        "Read security-relevant settings",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::SettingsWrite,
        "management.setting.write",
        "setting.write",
        "Update security-relevant settings",
        ManagementRoleEligibility::OWNER,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::AuditRead,
        "management.audit.read",
        "audit.read",
        "Read security audit events",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::PermissionRead,
        "management.permission.read",
        "permission.read",
        "Read permission catalog",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::PermissionWrite,
        "management.permission.write",
        "permission.write",
        "Create or update custom permission definitions",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::RolesRead,
        "management.role.read",
        "role.read",
        "Read business roles",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::RolesWrite,
        "management.role.write",
        "role.write",
        "Create or update business roles and their permissions",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::RoleAssignmentsRead,
        "management.role_assignment.read",
        "role_assignment.read",
        "Read user business role assignments",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::RoleAssignmentsWrite,
        "management.role_assignment.write",
        "role_assignment.write",
        "Assign or revoke user business roles",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::GroupsRead,
        "management.group.read",
        "group.read",
        "Read user groups",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::GroupsWrite,
        "management.group.write",
        "group.write",
        "Create, update, enable, or disable user groups",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::GroupMembershipsRead,
        "management.group_membership.read",
        "group_membership.read",
        "Read user group memberships",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::GroupMembershipsWrite,
        "management.group_membership.write",
        "group_membership.write",
        "Add or remove user group members",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::GroupRolesRead,
        "management.group_role.read",
        "group_role.read",
        "Read group role bindings",
        ManagementRoleEligibility::VIEWER,
        HumanAuthenticationRequirement::Aal2,
        ManagementFlowAllowance::USER_AND_CLIENT_CREDENTIALS,
    ),
    entry(
        ManagementScope::GroupRolesWrite,
        "management.group_role.write",
        "group_role.write",
        "Set or revoke group role bindings",
        ManagementRoleEligibility::ADMIN,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
    entry(
        ManagementScope::PermissionDelegate,
        "management.permission.delegate",
        "permission.delegate",
        "Delegate a registered permission beyond the caller's current access",
        ManagementRoleEligibility::OWNER,
        HumanAuthenticationRequirement::RecentAal2,
        ManagementFlowAllowance::USER_ONLY,
    ),
];

/// Scopes that must never be issued to machine clients in the first release.
pub const HUMAN_ONLY_SCOPES: [ManagementScope; 17] = [
    ManagementScope::CredentialsRevoke,
    ManagementScope::CredentialsReset,
    ManagementScope::ClientCredentialsCreate,
    ManagementScope::ClientCredentialsRotate,
    ManagementScope::ClientCredentialsRevoke,
    ManagementScope::AdministratorsRead,
    ManagementScope::AdministratorsWrite,
    ManagementScope::ClientGrantsRead,
    ManagementScope::ClientGrantsWrite,
    ManagementScope::SettingsWrite,
    ManagementScope::PermissionWrite,
    ManagementScope::RolesWrite,
    ManagementScope::RoleAssignmentsWrite,
    ManagementScope::GroupsWrite,
    ManagementScope::GroupMembershipsWrite,
    ManagementScope::GroupRolesWrite,
    ManagementScope::PermissionDelegate,
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagementCatalogError {
    #[error("management catalog contains duplicate scope {0}")]
    DuplicateScope(&'static str),
    #[error("management catalog contains duplicate name {0}")]
    DuplicateName(&'static str),
    #[error("management catalog entry has an invalid reserved name: {0}")]
    InvalidName(&'static str),
    #[error("management catalog entry is not marked reserved: {0}")]
    NotReserved(&'static str),
    #[error("owner eligibility is not explicit for {0}")]
    OwnerNotExhaustive(&'static str),
    #[error("role eligibility is not monotonic for {0}")]
    NonMonotonicRole(&'static str),
    #[error("human-only scope is exposed to machine clients: {0}")]
    HumanOnlyMachineScope(&'static str),
    #[error("management catalog name is not a three-segment management name: {0}")]
    InvalidShape(&'static str),
    #[error("management catalog is missing a definition for {0}")]
    MissingDefinition(&'static str),
}

/// Validate catalog coverage, explicit role membership, M2M boundaries and
/// reserved naming. Seeds/tests call this before writing catalog rows.
pub fn validate_catalog() -> Result<(), ManagementCatalogError> {
    let mut names = std::collections::HashSet::new();
    let mut scopes = std::collections::HashSet::new();

    for definition in &MANAGEMENT_SCOPES {
        if !scopes.insert(definition.scope) {
            return Err(ManagementCatalogError::DuplicateScope(definition.name));
        }
        if !names.insert(definition.name) {
            return Err(ManagementCatalogError::DuplicateName(definition.name));
        }
        if !definition.reserved {
            return Err(ManagementCatalogError::NotReserved(definition.name));
        }
        if !is_reserved_management_name(definition.name) {
            return Err(ManagementCatalogError::InvalidName(definition.name));
        }
        if !valid_management_name_shape(definition.name) {
            return Err(ManagementCatalogError::InvalidShape(definition.name));
        }
        // Owner is explicit on every entry, never derived from a wildcard.
        if !definition.roles.is_owner_eligible() {
            return Err(ManagementCatalogError::OwnerNotExhaustive(definition.name));
        }
        if definition.roles.allows(AdministratorRole::Viewer)
            && !definition.roles.allows(AdministratorRole::Admin)
        {
            return Err(ManagementCatalogError::NonMonotonicRole(definition.name));
        }
        if definition.roles.allows(AdministratorRole::Admin)
            && !definition.roles.allows(AdministratorRole::Owner)
        {
            return Err(ManagementCatalogError::NonMonotonicRole(definition.name));
        }
        if definition.m2m_allowed() {
            if definition.scope.is_human_only() {
                return Err(ManagementCatalogError::HumanOnlyMachineScope(
                    definition.name,
                ));
            }
        }
    }

    for scope in ManagementScope::ALL {
        if !MANAGEMENT_SCOPES
            .iter()
            .any(|definition| definition.scope == scope)
        {
            return Err(ManagementCatalogError::MissingDefinition(scope.name()));
        }
    }

    Ok(())
}

/// Deterministic fingerprint of the trusted catalog's *security* semantics.
///
/// The value covers each scope's stable name, action, explicit role
/// eligibility, human-authentication requirement, machine/user flow allowance,
/// owner-target sensitivity and the explicit human-only set. Display text,
/// descriptions, database rows, record optimistic-lock versions and timestamps
/// never participate.
///
/// It is an equality token for issued authorization snapshots, not a counter or
/// persisted policy state. Any semantic catalog change produces a different
/// fingerprint; changing only translations or ordering does not.
#[must_use]
pub fn policy_fingerprint() -> PolicyVersion {
    let mut entries = Vec::with_capacity(MANAGEMENT_SCOPES.len() + HUMAN_ONLY_SCOPES.len());
    for definition in MANAGEMENT_SCOPES {
        entries.push(format!(
            "scope|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            definition.name,
            definition.action,
            definition.roles.allows(AdministratorRole::Viewer),
            definition.roles.allows(AdministratorRole::Admin),
            definition.roles.allows(AdministratorRole::Owner),
            definition.human_authentication.as_str(),
            definition.flows.user_authorization_code,
            definition.flows.confidential_client_credentials,
            definition.scope.is_owner_target_sensitive(),
        ));
    }
    for scope in HUMAN_ONLY_SCOPES {
        entries.push(format!("human-only|{}", scope.name()));
    }
    entries.sort_unstable();
    PolicyVersion::from_uuid(deterministic_oid(&format!(
        "identity/authorization/catalog-policy/v1/{}",
        entries.join("\n")
    )))
}

fn valid_management_name_shape(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(MANAGEMENT_SCOPE_PREFIX) else {
        return false;
    };
    let mut segments = rest.split('.');
    let (Some(resource), Some(action), None) = (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    valid_segment(resource) && valid_segment(action)
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[must_use]
pub fn scopes_for_role(role: AdministratorRole) -> Vec<ManagementScope> {
    ManagementScope::ALL
        .into_iter()
        .filter(|scope| scope.allows_role(role))
        .collect()
}

#[must_use]
pub fn m2m_allowed_scopes() -> Vec<ManagementScope> {
    ManagementScope::ALL
        .into_iter()
        .filter(|scope| scope.m2m_allowed())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        HUMAN_ONLY_SCOPES, HumanAuthenticationRequirement, ManagementScope, ManagementScopeError,
        is_reserved_management_name, m2m_allowed_scopes, policy_fingerprint, validate_catalog,
    };

    #[test]
    fn plural_management_resource_names_are_not_aliases() {
        for name in [
            "management.users.read",
            "management.sessions.read",
            "management.roles.write",
            "management.groups.write",
            "management.group_memberships.write",
            "management.client_credentials.rotate",
            "management.client.scopes",
        ] {
            assert!(
                ManagementScope::parse(name).is_err(),
                "unexpected alias: {name}"
            );
        }
    }

    #[test]
    fn policy_fingerprint_is_deterministic_and_covers_security_semantics() {
        let first = policy_fingerprint();
        let second = policy_fingerprint();
        assert_eq!(first, second);
        assert!(!first.as_uuid().is_nil());
        assert_eq!(first.as_uuid().get_version_num(), 8);
    }

    #[test]
    fn trusted_catalog_is_internally_consistent() {
        validate_catalog().expect("trusted catalog must be internally consistent");
    }

    #[test]
    fn machine_set_excludes_all_human_only_scopes() {
        let m2m: BTreeSet<_> = m2m_allowed_scopes().into_iter().collect();
        let human_only: BTreeSet<_> = HUMAN_ONLY_SCOPES.into_iter().collect();
        assert!(m2m.is_disjoint(&human_only));
        for scope in &m2m {
            assert!(!scope.is_human_only(), "{scope}");
            assert!(!matches!(
                scope.human_authentication(),
                HumanAuthenticationRequirement::None
            ));
        }
    }

    #[test]
    fn group_scopes_have_exact_authentication_and_machine_boundaries() {
        for scope in [
            ManagementScope::GroupsRead,
            ManagementScope::GroupMembershipsRead,
            ManagementScope::GroupRolesRead,
        ] {
            assert_eq!(
                scope.human_authentication(),
                HumanAuthenticationRequirement::Aal2,
                "{scope}"
            );
            assert!(scope.m2m_allowed(), "{scope}");
            assert!(!scope.is_human_only(), "{scope}");
        }
        for scope in [
            ManagementScope::GroupsWrite,
            ManagementScope::GroupMembershipsWrite,
            ManagementScope::GroupRolesWrite,
        ] {
            assert_eq!(
                scope.human_authentication(),
                HumanAuthenticationRequirement::RecentAal2,
                "{scope}"
            );
            assert!(!scope.m2m_allowed(), "{scope}");
            assert!(scope.is_human_only(), "{scope}");
        }
    }

    #[test]
    fn lookup_is_exact_match_only() {
        assert_eq!(
            ManagementScope::from_name("management.user.read"),
            Some(ManagementScope::UsersRead)
        );
        for name in [
            "management",
            "management.users",
            "management.user.read.extra",
            "management.user.read ",
            "Management.users.read",
            "managementx.users.read",
            "users.read",
        ] {
            assert_eq!(ManagementScope::from_name(name), None, "{name}");
        }
        assert_eq!(
            ManagementScope::parse("management.users").unwrap_err(),
            ManagementScopeError::ReservedPrefix
        );
        assert_eq!(
            ManagementScope::parse("users.read").unwrap_err(),
            ManagementScopeError::Unknown
        );
    }

    #[test]
    fn reserved_prefix_requires_the_dot() {
        assert!(is_reserved_management_name("management.user.read"));
        assert!(is_reserved_management_name("management.unknown"));
        assert!(!is_reserved_management_name("management"));
        assert!(!is_reserved_management_name("managementx.users.read"));
        assert!(!is_reserved_management_name("account.read"));
    }

    #[test]
    fn owner_target_sensitive_scopes_are_explicit() {
        let expected = [
            ManagementScope::UsersUpdate,
            ManagementScope::UsersState,
            ManagementScope::UsersRevokeAccess,
            ManagementScope::CredentialsRevoke,
            ManagementScope::CredentialsReset,
            ManagementScope::AdministratorsWrite,
        ];
        for scope in ManagementScope::ALL {
            assert_eq!(
                scope.is_owner_target_sensitive(),
                expected.contains(&scope),
                "{scope}"
            );
        }
    }
}
