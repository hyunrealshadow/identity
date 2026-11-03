//! Historical administrator bindings.
//!
//! Instance management authority is now expressed only by the unified RBAC
//! graph. The binding model remains decodable so old audit/revocation records
//! can be inspected, but it never authorizes runtime access and there is no
//! machine management grant. Machine access is bounded exclusively by live
//! `client_scope` rows belonging to the target resource.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    authorization::{
        actor::{ActorContext, ActorPrincipal},
        audit::{AuditSubject, AuditSubjectKind, AuthorizationAuditContext},
        ids::{AdministratorBindingOid, AuthorizationVersion},
    },
    user::UserOid,
};

pub use crate::authorization::catalog::AdministratorRole;

/// Optional operator reason annotation. Reasons are audit annotations, not an
/// approval precondition: an absent or blank value is represented by an empty
/// string. Voluntarily supplied text is trimmed and bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantReason(String);

/// Maximum length of a voluntarily supplied grant reason annotation.
pub const MAX_GRANT_REASON_LENGTH: usize = 1_000;

impl GrantReason {
    pub fn new(value: impl Into<String>) -> Result<Self, GrantReasonError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.chars().count() > MAX_GRANT_REASON_LENGTH {
            return Err(GrantReasonError::TooLong);
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantReasonError {
    #[error("grant reason is too long")]
    TooLong,
}

/// Grant provenance shared by human bindings and machine grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantMetadata {
    pub reason: GrantReason,
    pub granted_by_user_oid: Option<UserOid>,
    pub granted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdministratorBinding {
    pub oid: AdministratorBindingOid,
    pub user_oid: UserOid,
    pub role: AdministratorRole,
    pub version: AuthorizationVersion,
    pub metadata: GrantMetadata,
    pub updated_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl AdministratorBinding {
    #[must_use]
    pub fn new(
        oid: AdministratorBindingOid,
        user_oid: UserOid,
        role: AdministratorRole,
        metadata: GrantMetadata,
    ) -> Self {
        Self {
            oid,
            user_oid,
            role,
            version: AuthorizationVersion::fresh(),
            metadata,
            updated_at: None,
            enabled: true,
            revoked_at: None,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && self.revoked_at.is_none()
    }

    pub fn change_role(
        &mut self,
        role: AdministratorRole,
        now: DateTime<Utc>,
    ) -> Result<(), GrantLifecycleError> {
        if !self.is_active() {
            return Err(GrantLifecycleError::NotActive);
        }
        if self.role == role {
            return Ok(());
        }
        self.role = role;
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), GrantLifecycleError> {
        if !self.is_active() {
            return Err(GrantLifecycleError::AlreadyRevoked);
        }
        self.enabled = false;
        self.revoked_at = Some(now);
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantLifecycleError {
    #[error("grant is not active")]
    NotActive,
    #[error("grant is already revoked")]
    AlreadyRevoked,
}

/// Audit context helper so adapters cannot accidentally use a target or a
/// display name as the actor.
#[must_use]
pub fn administrator_audit_context(
    actor: &ActorContext,
    action: &'static str,
    target_binding: AdministratorBindingOid,
    reason: &GrantReason,
) -> AuthorizationAuditContext {
    let actor_subject = match &actor.principal {
        ActorPrincipal::User { user_oid, .. } => {
            AuditSubject::new(AuditSubjectKind::User, user_oid.0)
        }
        ActorPrincipal::Client { client_oid } => {
            AuditSubject::new(AuditSubjectKind::Client, *client_oid)
        }
    };
    AuthorizationAuditContext::new(
        actor_subject,
        action,
        AuditSubject::new(AuditSubjectKind::Binding, target_binding.0),
        reason.as_str(),
        actor.request_id.clone(),
        actor.trace_id.clone(),
    )
}

/// Commands consumed by the transactional administrator repository.
#[derive(Debug, Clone)]
pub struct AssignAdministrator {
    pub user_oid: UserOid,
    pub role: AdministratorRole,
    pub reason: GrantReason,
    pub audit: AuthorizationAuditContext,
    pub expected_version: Option<AuthorizationVersion>,
}

#[derive(Debug, Clone)]
pub struct UpdateAdministratorRole {
    pub binding_oid: AdministratorBindingOid,
    pub role: AdministratorRole,
    pub reason: GrantReason,
    pub expected_version: AuthorizationVersion,
    pub audit: AuthorizationAuditContext,
}

#[derive(Debug, Clone)]
pub struct RevokeAdministrator {
    pub binding_oid: AdministratorBindingOid,
    pub reason: GrantReason,
    pub expected_version: AuthorizationVersion,
    pub audit: AuthorizationAuditContext,
}

/// Domain outcomes returned by historical binding mutations. Storage failures
/// remain separate `Result::Err` values and never expose SQL text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdministratorMutationOutcome {
    Assigned(AdministratorBinding),
    RoleUpdated(AdministratorBinding),
    Revoked(AdministratorBinding),
    UserNotFound,
    BindingNotFound,
    AlreadyAssigned,
    AlreadyRevoked,
    VersionConflict { current: AuthorizationVersion },
    LastOwnerProtected,
}

/// Snapshot helper used in tests and audit explanations. It stores the exact
/// binding OID and version, never a role name or an array index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdministratorBindingRef {
    pub binding_oid: AdministratorBindingOid,
    pub version: AuthorizationVersion,
}

impl From<&AdministratorBinding> for AdministratorBindingRef {
    fn from(binding: &AdministratorBinding) -> Self {
        Self {
            binding_oid: binding.oid,
            version: binding.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        AdministratorBinding, AdministratorRole, GrantMetadata, GrantReason, GrantReasonError,
    };
    use crate::{authorization::ids::AdministratorBindingOid, user::UserOid};

    fn metadata(reason: &str) -> GrantMetadata {
        GrantMetadata {
            reason: GrantReason::new(reason).unwrap(),
            granted_by_user_oid: Some(UserOid(Uuid::new_v4())),
            granted_at: Utc.timestamp_opt(1_000, 0).single().unwrap(),
        }
    }

    #[test]
    fn grant_reason_accepts_blank_as_empty_and_round_trips() {
        let reason = GrantReason::new("   ").expect("blank reason is optional");
        assert_eq!(reason.as_str(), "");
        let encoded = serde_json::to_string(&reason).unwrap();
        assert_eq!(encoded, "\"\"");
        let decoded: GrantReason = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, reason);

        assert_eq!(
            GrantReason::new("  supplied annotation  ")
                .unwrap()
                .as_str(),
            "supplied annotation"
        );
        assert_eq!(
            GrantReason::new("x".repeat(1_001)),
            Err(GrantReasonError::TooLong)
        );
    }

    #[test]
    fn human_binding_lifecycle_bumps_version_and_rejects_double_revoke() {
        let mut binding = AdministratorBinding::new(
            AdministratorBindingOid::new(),
            UserOid(Uuid::new_v4()),
            AdministratorRole::Admin,
            metadata("initial"),
        );
        let initial = binding.version;
        binding
            .change_role(AdministratorRole::Owner, Utc::now())
            .unwrap();
        let after_role = binding.version;
        assert_ne!(after_role, initial);
        binding.revoke(Utc::now()).unwrap();
        assert_ne!(binding.version, after_role);
        assert!(!binding.is_active());
        assert!(binding.revoke(Utc::now()).is_err());
    }
}
