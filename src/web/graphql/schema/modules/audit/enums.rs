//! GraphQL mirrors of the domain audit enums. `remote` makes the compiler
//! reject any variant that is missing on either side.

use async_graphql::Enum;
use identity_domain::audit as domain;

/// Which audit log an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditCategory", remote = "domain::AuditCategory")]
pub(crate) enum AuditCategory {
    Management,
    Account,
    SignIn,
    Authorization,
}

/// Result of the audited attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditOutcome", remote = "domain::AuditOutcome")]
pub(crate) enum AuditOutcome {
    Success,
    Failure,
}

/// Why an attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditFailureReason", remote = "domain::AuditFailureReason")]
pub(crate) enum AuditFailureReason {
    InvalidCredential,
    InvalidOtp,
    InvalidRecoveryCode,
    ReplayDetected,
    UnknownAccount,
    AccountLocked,
    AccountDisabled,
}

/// Who performed the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditActorKind", remote = "domain::AuditActorKind")]
pub(crate) enum AuditActorKind {
    User,
    Client,
    System,
    Anonymous,
}

/// Type of the object an action applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditTargetKind", remote = "domain::AuditTargetKind")]
pub(crate) enum AuditTargetKind {
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

/// How a person authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditAuthMethod", remote = "domain::AuditAuthMethod")]
pub(crate) enum AuditAuthMethod {
    Password,
    Otp,
    Passkey,
    RecoveryCode,
}

/// A changed attribute of an audited object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditField", remote = "domain::AuditField")]
pub(crate) enum AuditField {
    Name,
    Names,
    Description,
    Descriptions,
    Enabled,
    Username,
    Email,
    EmailVerified,
    RequiredActions,
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

/// A stable public audit action, named object first, then verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "AuditAction", remote = "domain::AuditAction")]
pub(crate) enum AuditAction {
    UserCreate,
    UserInvite,
    UserUpdate,
    UserEnable,
    UserDisable,
    UserUnlock,
    UserPasswordReset,
    UserMfaReset,
    UserSessionRevoke,
    UserDelete,
    UserRoleGrant,
    UserRoleRevoke,
    GroupCreate,
    GroupUpdate,
    GroupEnable,
    GroupDisable,
    GroupDelete,
    GroupMemberAdd,
    GroupMemberRemove,
    GroupRoleUpdate,
    RoleCreate,
    RoleUpdate,
    RoleEnable,
    RoleDisable,
    RolePermissionUpdate,
    ResourceCreate,
    ResourceUpdate,
    ResourceEnable,
    ResourceDisable,
    ScopeCreate,
    ScopeUpdate,
    ScopeEnable,
    ScopeDisable,
    ClientCreate,
    ClientUpdate,
    ClientDelete,
    ClientEnable,
    ClientDisable,
    ClientSecretCreate,
    ClientSecretRotate,
    ClientPublicKeyAdd,
    ClientJwksUriSet,
    ClientCredentialRevoke,
    ClientScopeUpdate,
    ClientRegister,
    ClientRegistrationUpdate,
    ClientRegistrationDelete,
    KeyCreate,
    KeyRotate,
    KeyRevoke,
    SettingProtocolUpdate,
    SettingAuthenticationUpdate,
    SettingEmailUpdate,
    SettingEmailTemplateUpdate,
    AccountProfileUpdate,
    AccountIdentifierUpdate,
    AccountEmailVerify,
    AccountPasswordChange,
    AccountPasswordReset,
    AccountRegister,
    AccountInvitationAccept,
    AccountCredentialReplace,
    AccountTotpEnable,
    AccountTotpDisable,
    AccountRecoveryCodeRegenerate,
    AccountPasskeyAdd,
    AccountPasskeyUpdate,
    AccountPasskeyRemove,
    SignIn,
    AccountLock,
    SessionReauthenticate,
    SessionRevoke,
    SessionReuse,
    ClientAuthenticate,
    ConsentGrant,
    ConsentDeny,
    TokenRevoke,
    AccessTokenRevoke,
    TokenReplay,
    DeviceApprove,
    DeviceDeny,
    DeviceRevoke,
}
