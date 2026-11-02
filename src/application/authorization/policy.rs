//! Application authorization policy for instance management.
//!
//! This is a pure policy surface consumed by later GraphQL Guards and mutation
//! use cases. It does not depend on SeaORM, HTTP or GraphQL. Adapters load the
//! current binding/grant and policy version, then pass them here.

use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use identity_domain::{
    authorization::{
        actor::{ActorContext, ActorPrincipal},
        authority::{ClientScopeAuthority, UserPermissionAuthority},
        catalog::{AdministratorRole, HumanAuthenticationRequirement, ManagementScope},
        ids::{AuthorizationVersion, PolicyVersion},
        snapshot::{
            ManagementAuthorizationSnapshot, ManagementGrantKind, SnapshotValidationError,
            validate_user_permission_snapshot,
        },
    },
    user::UserOid,
};

pub const DEFAULT_RECENT_AAL2_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementTargetKind {
    Instance,
    User,
    Client,
    Resource,
    Setting,
    AdministratorBinding,
    Session,
}

impl ManagementTargetKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::User => "user",
            Self::Client => "client",
            Self::Resource => "resource",
            Self::Setting => "setting",
            Self::AdministratorBinding => "administrator_binding",
            Self::Session => "session",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementTarget {
    pub kind: ManagementTargetKind,
    pub oid: Uuid,
    /// Only meaningful for a user target. Set from authoritative state, never
    /// from client input.
    pub is_instance_owner: bool,
}

impl ManagementTarget {
    #[must_use]
    pub const fn instance() -> Self {
        Self {
            kind: ManagementTargetKind::Instance,
            oid: Uuid::nil(),
            is_instance_owner: false,
        }
    }

    #[must_use]
    pub const fn user(user: UserOid, is_instance_owner: bool) -> Self {
        Self {
            kind: ManagementTargetKind::User,
            oid: user.0,
            is_instance_owner,
        }
    }
}

/// Current authoritative management authority.
///
/// Human authority is the unified RBAC permission set. Machine authority is the
/// live `client_scope` ceiling for the GraphQL resource; it is not a grant row,
/// not a client-management switch and never borrows human RBAC or MFA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentManagementAuthority {
    UserPermissions(UserPermissionAuthority),
    ClientScopes(ClientScopeAuthority),
}

impl CurrentManagementAuthority {
    #[must_use]
    pub fn kind(&self) -> Option<ManagementGrantKind> {
        match self {
            Self::UserPermissions(_) => Some(ManagementGrantKind::UserRbac),
            Self::ClientScopes(_) => None,
        }
    }

    #[must_use]
    pub fn oid(&self) -> Uuid {
        match self {
            Self::UserPermissions(authority) => authority.user_oid.0,
            Self::ClientScopes(authority) => authority.client_oid,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagementAuthorizationRequest<'a> {
    pub actor: &'a ActorContext,
    pub token_scopes: &'a BTreeSet<ManagementScope>,
    pub required: ManagementScope,
    pub target: ManagementTarget,
    pub current_authority: Option<&'a CurrentManagementAuthority>,
    pub snapshot: Option<&'a ManagementAuthorizationSnapshot>,
    /// Immutable machine client-boundary identity carried by the credential,
    /// when one is available. Human credentials use `snapshot` instead.
    pub credential_client_boundary: Option<PolicyVersion>,
    pub current_policy_version: PolicyVersion,
    pub now: DateTime<Utc>,
    pub recent_aal2_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementAuthorizationDecision {
    pub scope: ManagementScope,
    pub grant_oid: Uuid,
    pub grant_version: AuthorizationVersion,
    pub role: Option<AdministratorRole>,
    pub required_authentication: HumanAuthenticationRequirement,
}

#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagementAuthorizationError {
    #[error("a user or client principal is required")]
    MissingPrincipal,
    #[error("the token does not carry the required management scope: {required}")]
    InsufficientScope { required: ManagementScope },
    #[error("no current management grant authorizes this actor")]
    NoCurrentGrant,
    #[error("the current management grant is revoked or disabled")]
    GrantTombstoned,
    #[error("the machine client scope boundary is no longer authoritative")]
    ClientScopeBoundaryMismatch,
    #[error(
        "the management scope is human-only and cannot be used by a machine principal: {scope}"
    )]
    HumanOnlyCapability { scope: ManagementScope },
    #[error("the user role is not eligible for this management scope: {role}")]
    RoleNotAuthorized { role: AdministratorRole },
    #[error("the user does not have the required management permission: {permission}")]
    PermissionNotAuthorized { permission: ManagementScope },
    #[error("the management authorization snapshot is missing")]
    SnapshotMissing,
    #[error("the management authorization snapshot has the wrong grant kind")]
    SnapshotKindMismatch,
    #[error("the management authorization snapshot is stale")]
    SnapshotStale {
        snapshot: AuthorizationVersion,
        current: AuthorizationVersion,
    },
    #[error("the management authorization snapshot version is not authoritative")]
    SnapshotVersionInvalid {
        snapshot: AuthorizationVersion,
        current: AuthorizationVersion,
    },
    #[error("the management authorization grant was recreated; the snapshot OID cannot be reused")]
    SnapshotOidMismatch,
    #[error("the management authorization policy version changed")]
    SnapshotPolicyMismatch,
    #[error("the management authorization role changed")]
    SnapshotRoleMismatch,
    #[error("the management authorization permission set changed")]
    SnapshotPermissionsMismatch,
    #[error("the management grant is expired or revoked")]
    SnapshotExpired,
    #[error("this management scope requires AAL2 human authentication")]
    AuthenticationRequired {
        required: HumanAuthenticationRequirement,
    },
    #[error("this management scope requires recent AAL2 human authentication")]
    RecentAuthenticationRequired,
    #[error("the target is not permitted for this actor or scope")]
    TargetForbidden,
    #[error("the target describing an owner is invalid for this target kind")]
    InvalidTarget,
    #[error("the token contains an unknown reserved management scope: {scope}")]
    InvalidTokenScope { scope: String },
    #[error("the management authority record is internally inconsistent")]
    InconsistentAuthority,
    #[error("the token scope could not be authorized")]
    TokenScopeNotAuthorized,
}

impl std::fmt::Debug for ManagementAuthorizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// Exact-match conversion of token scope names. Non-management scopes are
/// ignored here; unknown names with the reserved prefix are rejected.
pub fn parse_token_management_scopes<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<ManagementScope>, ManagementAuthorizationError> {
    let mut scopes = BTreeSet::new();
    for name in names {
        if let Some(scope) = ManagementScope::from_name(name) {
            scopes.insert(scope);
        } else if identity_domain::authorization::catalog::is_reserved_management_name(name) {
            return Err(ManagementAuthorizationError::InvalidTokenScope {
                scope: name.to_owned(),
            });
        }
    }
    Ok(scopes)
}

/// Evaluate one management operation. The caller must pass authoritative
/// current state and the credential's immutable snapshot; this function never
/// derives authority from scope names alone.
pub fn evaluate_management_authority(
    request: &ManagementAuthorizationRequest<'_>,
) -> Result<ManagementAuthorizationDecision, ManagementAuthorizationError> {
    let definition = request.required.definition();

    if request.target.is_instance_owner && request.target.kind != ManagementTargetKind::User {
        return Err(ManagementAuthorizationError::InvalidTarget);
    }

    if !request.token_scopes.contains(&request.required) {
        return Err(ManagementAuthorizationError::InsufficientScope {
            required: request.required,
        });
    }

    let current = request
        .current_authority
        .ok_or(ManagementAuthorizationError::NoCurrentGrant)?;

    match (&request.actor.principal, current) {
        (
            ActorPrincipal::User {
                user_oid,
                authentication,
            },
            CurrentManagementAuthority::UserPermissions(authority),
        ) => {
            let snapshot = request
                .snapshot
                .ok_or(ManagementAuthorizationError::SnapshotMissing)?;
            if authority.user_oid != *user_oid {
                return Err(ManagementAuthorizationError::NoCurrentGrant);
            }
            if !authority.authorizes(request.required) {
                return Err(ManagementAuthorizationError::PermissionNotAuthorized {
                    permission: request.required,
                });
            }
            validate_user_snapshot(snapshot, authority, request.current_policy_version)?;
            enforce_human_authentication(
                *authentication,
                definition.human_authentication,
                request.now,
                request.recent_aal2_ttl,
            )?;
            Ok(ManagementAuthorizationDecision {
                scope: request.required,
                grant_oid: authority.user_oid.0,
                grant_version: authority.version,
                role: None,
                required_authentication: definition.human_authentication,
            })
        }
        (
            ActorPrincipal::Client { client_oid },
            CurrentManagementAuthority::ClientScopes(authority),
        ) => {
            if authority.client_oid != *client_oid {
                return Err(ManagementAuthorizationError::NoCurrentGrant);
            }
            // The live ceiling is the only machine authority. It may not grow
            // an already-issued token and it may not borrow human RBAC.
            if !request
                .token_scopes
                .iter()
                .all(|scope| authority.authorizes(*scope))
            {
                return Err(ManagementAuthorizationError::ClientScopeBoundaryMismatch);
            }
            if !authority.authorizes(request.required) {
                return Err(ManagementAuthorizationError::PermissionNotAuthorized {
                    permission: request.required,
                });
            }
            if request.required.is_human_only() || !request.required.m2m_allowed() {
                return Err(ManagementAuthorizationError::HumanOnlyCapability {
                    scope: request.required,
                });
            }
            if request.target.is_instance_owner && request.required.is_owner_target_sensitive() {
                return Err(ManagementAuthorizationError::TargetForbidden);
            }
            if let Some(issued) = request.credential_client_boundary {
                if issued != authority.boundary {
                    return Err(ManagementAuthorizationError::ClientScopeBoundaryMismatch);
                }
            }
            // Machine principals never claim human AAL2. Eligibility is the
            // catalog's explicit machine allowance plus the live ceiling.
            Ok(ManagementAuthorizationDecision {
                scope: request.required,
                grant_oid: authority.client_oid,
                grant_version: AuthorizationVersion::from_uuid(authority.boundary.as_uuid()),
                role: None,
                required_authentication: HumanAuthenticationRequirement::None,
            })
        }
        (ActorPrincipal::Client { .. }, CurrentManagementAuthority::UserPermissions(_))
        | (ActorPrincipal::User { .. }, CurrentManagementAuthority::ClientScopes(_)) => {
            Err(ManagementAuthorizationError::SnapshotKindMismatch)
        }
    }
}

fn validate_user_snapshot(
    snapshot: &ManagementAuthorizationSnapshot,
    authority: &UserPermissionAuthority,
    policy_version: PolicyVersion,
) -> Result<(), ManagementAuthorizationError> {
    validate_user_permission_snapshot(snapshot, Some(authority), policy_version)
        .map_err(map_snapshot_error)
}

fn map_snapshot_error(error: SnapshotValidationError) -> ManagementAuthorizationError {
    match error {
        SnapshotValidationError::GrantNotFound => ManagementAuthorizationError::NoCurrentGrant,
        SnapshotValidationError::GrantKindMismatch => {
            ManagementAuthorizationError::SnapshotKindMismatch
        }
        SnapshotValidationError::RetiredGrantKind | SnapshotValidationError::Tombstoned => {
            ManagementAuthorizationError::SnapshotExpired
        }
        SnapshotValidationError::OidMismatch { .. } => {
            ManagementAuthorizationError::SnapshotOidMismatch
        }
        SnapshotValidationError::VersionMismatch { snapshot, current } => {
            ManagementAuthorizationError::SnapshotStale { snapshot, current }
        }
        SnapshotValidationError::PolicyVersionMismatch { .. } => {
            ManagementAuthorizationError::SnapshotPolicyMismatch
        }
        SnapshotValidationError::RoleMismatch => ManagementAuthorizationError::SnapshotRoleMismatch,
        SnapshotValidationError::PermissionsMismatch => {
            ManagementAuthorizationError::SnapshotPermissionsMismatch
        }
    }
}

fn enforce_human_authentication(
    authentication: identity_domain::authorization::actor::HumanAuthenticationContext,
    required: HumanAuthenticationRequirement,
    now: DateTime<Utc>,
    recent_ttl: Duration,
) -> Result<(), ManagementAuthorizationError> {
    if required.requires_aal2() && !authentication.meets_aal2() {
        return Err(ManagementAuthorizationError::AuthenticationRequired { required });
    }
    if required.requires_recent_aal2() && !authentication.is_recent_aal2(now, recent_ttl) {
        return Err(ManagementAuthorizationError::RecentAuthenticationRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        CurrentManagementAuthority, ManagementAuthorizationError, ManagementAuthorizationRequest,
        ManagementTarget, evaluate_management_authority, parse_token_management_scopes,
    };
    use identity_domain::{
        authorization::{
            actor::{ActorContext, HumanAuthenticationContext, RequestId},
            authority::{ClientScopeAuthority, UserPermissionAuthority},
            catalog::{HumanAuthenticationRequirement, ManagementScope},
            ids::{AuthorizationVersion, PolicyVersion},
            snapshot::ManagementAuthorizationSnapshot,
        },
        user::UserOid,
    };

    fn at(seconds: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    fn authority(
        user: UserOid,
        permissions: impl IntoIterator<Item = ManagementScope>,
    ) -> UserPermissionAuthority {
        UserPermissionAuthority::new(user, AuthorizationVersion::new(), permissions)
    }

    fn actor(user: UserOid, assurance: HumanAuthenticationContext) -> ActorContext {
        ActorContext::for_user(user, assurance, RequestId::new("request-1").unwrap(), None)
    }

    fn request<'a>(
        actor: &'a ActorContext,
        token_scopes: &'a BTreeSet<ManagementScope>,
        required: ManagementScope,
        target: ManagementTarget,
        current: &'a CurrentManagementAuthority,
        snapshot: &'a ManagementAuthorizationSnapshot,
        now: chrono::DateTime<Utc>,
    ) -> ManagementAuthorizationRequest<'a> {
        ManagementAuthorizationRequest {
            actor,
            token_scopes,
            required,
            target,
            current_authority: Some(current),
            snapshot: Some(snapshot),
            credential_client_boundary: None,
            current_policy_version: snapshot.policy_version,
            now,
            recent_aal2_ttl: std::time::Duration::from_secs(300),
        }
    }

    fn scopes(values: &[ManagementScope]) -> BTreeSet<ManagementScope> {
        values.iter().copied().collect()
    }

    #[test]
    fn read_permission_with_aal2_can_read_but_not_write() {
        let user = UserOid(Uuid::new_v4());
        let authority = authority(user, [ManagementScope::UsersRead]);
        let snapshot =
            ManagementAuthorizationSnapshot::for_user_permissions(&authority, PolicyVersion::new());
        let current = CurrentManagementAuthority::UserPermissions(authority);
        let actor = actor(user, HumanAuthenticationContext::aal2(Some(at(990))));
        let token = scopes(&[ManagementScope::UsersRead, ManagementScope::UsersCreate]);
        let decision = evaluate_management_authority(&request(
            &actor,
            &token,
            ManagementScope::UsersRead,
            ManagementTarget::instance(),
            &current,
            &snapshot,
            at(1_000),
        ))
        .unwrap();
        assert_eq!(decision.scope, ManagementScope::UsersRead);
        assert_eq!(
            evaluate_management_authority(&request(
                &actor,
                &token,
                ManagementScope::UsersCreate,
                ManagementTarget::instance(),
                &current,
                &snapshot,
                at(1_000),
            )),
            Err(ManagementAuthorizationError::PermissionNotAuthorized {
                permission: ManagementScope::UsersCreate
            })
        );
    }

    #[test]
    fn recent_aal2_is_strict_for_sensitive_scope() {
        let user = UserOid(Uuid::new_v4());
        let authority = authority(user, [ManagementScope::CredentialsReset]);
        let snapshot =
            ManagementAuthorizationSnapshot::for_user_permissions(&authority, PolicyVersion::new());
        let current = CurrentManagementAuthority::UserPermissions(authority);
        let token = scopes(&[ManagementScope::CredentialsReset]);
        let old_aal2 = actor(user, HumanAuthenticationContext::aal2(Some(at(100))));
        assert_eq!(
            evaluate_management_authority(&request(
                &old_aal2,
                &token,
                ManagementScope::CredentialsReset,
                ManagementTarget::instance(),
                &current,
                &snapshot,
                at(1_000),
            )),
            Err(ManagementAuthorizationError::RecentAuthenticationRequired)
        );
        let aal1 = actor(user, HumanAuthenticationContext::aal1(Some(at(999))));
        assert_eq!(
            evaluate_management_authority(&request(
                &aal1,
                &token,
                ManagementScope::CredentialsReset,
                ManagementTarget::instance(),
                &current,
                &snapshot,
                at(1_000),
            )),
            Err(ManagementAuthorizationError::AuthenticationRequired {
                required: HumanAuthenticationRequirement::RecentAal2
            })
        );
    }

    #[test]
    fn machine_uses_live_client_scopes_without_human_rbac_or_mfa() {
        let client_oid = Uuid::new_v4();
        let boundary = PolicyVersion::new();
        let authority = CurrentManagementAuthority::ClientScopes(ClientScopeAuthority::new(
            client_oid,
            [
                ManagementScope::UsersRead,
                ManagementScope::CredentialsReset,
            ],
            boundary,
        ));
        let actor =
            ActorContext::for_client(client_oid, RequestId::new("request-machine").unwrap(), None);
        let token = scopes(&[ManagementScope::UsersRead]);
        let request = ManagementAuthorizationRequest {
            actor: &actor,
            token_scopes: &token,
            required: ManagementScope::UsersRead,
            target: ManagementTarget::instance(),
            current_authority: Some(&authority),
            snapshot: None,
            credential_client_boundary: Some(boundary),
            current_policy_version: PolicyVersion::new(),
            now: at(1_000),
            recent_aal2_ttl: std::time::Duration::from_secs(300),
        };
        let decision = evaluate_management_authority(&request).unwrap();
        assert_eq!(decision.grant_oid, client_oid);
        assert_eq!(
            decision.required_authentication,
            HumanAuthenticationRequirement::None
        );

        let mut stale = request;
        stale.credential_client_boundary = Some(PolicyVersion::new());
        assert_eq!(
            evaluate_management_authority(&stale),
            Err(ManagementAuthorizationError::ClientScopeBoundaryMismatch)
        );

        let human_only = scopes(&[ManagementScope::CredentialsReset]);
        let denied = ManagementAuthorizationRequest {
            token_scopes: &human_only,
            required: ManagementScope::CredentialsReset,
            ..stale
        };
        assert_eq!(
            evaluate_management_authority(&denied),
            Err(ManagementAuthorizationError::HumanOnlyCapability {
                scope: ManagementScope::CredentialsReset
            })
        );
    }

    #[test]
    fn missing_token_scope_is_rejected() {
        let user = UserOid(Uuid::new_v4());
        let authority = authority(user, [ManagementScope::UsersRead]);
        let snapshot =
            ManagementAuthorizationSnapshot::for_user_permissions(&authority, PolicyVersion::new());
        let current = CurrentManagementAuthority::UserPermissions(authority);
        let actor = actor(user, HumanAuthenticationContext::aal2(Some(at(999))));
        let token = BTreeSet::new();
        assert_eq!(
            evaluate_management_authority(&request(
                &actor,
                &token,
                ManagementScope::UsersRead,
                ManagementTarget::instance(),
                &current,
                &snapshot,
                at(1_000),
            )),
            Err(ManagementAuthorizationError::InsufficientScope {
                required: ManagementScope::UsersRead
            })
        );
    }

    #[test]
    fn permission_holder_can_modify_recoverable_target_without_a_role_name() {
        // The actor's authority comes from an ordinary permission set. There is
        // no Owner/Admin role gate and no built-in group membership check.
        let actor_user = UserOid(Uuid::new_v4());
        let target = UserOid(Uuid::new_v4());
        let authority = authority(actor_user, [ManagementScope::UsersState]);
        let snapshot =
            ManagementAuthorizationSnapshot::for_user_permissions(&authority, PolicyVersion::new());
        let current = CurrentManagementAuthority::UserPermissions(authority);
        let actor = actor(actor_user, HumanAuthenticationContext::aal2(Some(at(999))));
        let token = scopes(&[ManagementScope::UsersState]);
        assert!(
            evaluate_management_authority(&request(
                &actor,
                &token,
                ManagementScope::UsersState,
                ManagementTarget::user(target, true),
                &current,
                &snapshot,
                at(1_000),
            ))
            .is_ok()
        );
    }

    #[test]
    fn stale_whole_user_generation_is_rejected() {
        let user = UserOid(Uuid::new_v4());
        let mut authority = authority(user, [ManagementScope::UsersRead]);
        let snapshot =
            ManagementAuthorizationSnapshot::for_user_permissions(&authority, PolicyVersion::new());
        authority.version = AuthorizationVersion::new();
        let current = CurrentManagementAuthority::UserPermissions(authority);
        let actor = actor(user, HumanAuthenticationContext::aal2(Some(at(999))));
        let token = scopes(&[ManagementScope::UsersRead]);
        assert!(matches!(
            evaluate_management_authority(&request(
                &actor,
                &token,
                ManagementScope::UsersRead,
                ManagementTarget::instance(),
                &current,
                &snapshot,
                at(1_000),
            )),
            Err(ManagementAuthorizationError::SnapshotStale { .. })
        ));
    }

    #[test]
    fn token_scope_parser_rejects_unknown_reserved_names() {
        assert_eq!(
            parse_token_management_scopes(["management.user.read", "openid"]).unwrap(),
            scopes(&[ManagementScope::UsersRead])
        );
        assert_eq!(
            parse_token_management_scopes(["management.users"]),
            Err(ManagementAuthorizationError::InvalidTokenScope {
                scope: "management.users".to_owned()
            })
        );
    }
}
