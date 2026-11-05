//! Owner lifecycle and owner-target protection contracts.
//!
//! Last-owner protection is a database-transaction invariant: the
//! implementation must acquire the owner lifecycle lock, read the authoritative
//! enabled/credential facts, evaluate these pure rules, and only then mutate.
//! Counting only enabled bindings is insufficient; a user without a usable
//! credential path is not a recoverable owner.

use std::time::Duration;

use crate::authorization::{
    actor::{ActorContext, ActorPrincipal},
    catalog::ManagementScope,
};

/// Facts gathered inside the mutation transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerLifecycleContext {
    /// Whether the target had an active owner binding before the change.
    pub target_was_active_owner: bool,
    /// Whether the target will still have an active owner binding after change.
    pub target_remains_active_owner: bool,
    /// Whether the target account was a usable owner (active owner binding,
    /// enabled user and a usable credential path) before the change.
    pub target_was_usable_owner: bool,
    /// Whether the target will still be a usable owner after the change.
    pub target_remains_usable_owner: bool,
    /// Number of other active owners, excluding the target.
    pub other_active_owner_count: u64,
    /// Number of other usable owners, excluding the target.
    pub other_usable_owner_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OwnerProtectionError {
    #[error("removing or disabling the last recoverable authorization administrator is forbidden")]
    LastOwnerProtected,
    #[error("the target authorization administrator cannot be modified by this actor")]
    OwnerTargetProtected,
}

/// Pure last-owner rule. It is intentionally conservative: an owner change that
/// removes the last usable owner path is always rejected.
pub fn ensure_usable_owner_survives(
    context: OwnerLifecycleContext,
) -> Result<(), OwnerProtectionError> {
    if context.target_was_active_owner
        && !context.target_remains_active_owner
        && context.other_active_owner_count == 0
    {
        return Err(OwnerProtectionError::LastOwnerProtected);
    }
    if context.target_was_usable_owner
        && !context.target_remains_usable_owner
        && context.other_usable_owner_count == 0
    {
        return Err(OwnerProtectionError::LastOwnerProtected);
    }
    Ok(())
}

/// Owner-target facts. High-risk changes to an owner require a human owner with
/// recent AAL2; machine grants and lower administrator roles cannot perform
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerTargetContext {
    pub target_is_owner: bool,
    pub actor_is_owner: bool,
    pub actor_is_machine: bool,
    pub actor_has_recent_aal2: bool,
}

pub fn ensure_owner_target_allowed(
    context: OwnerTargetContext,
) -> Result<(), OwnerProtectionError> {
    if !context.target_is_owner {
        return Ok(());
    }
    if context.actor_is_machine || !context.actor_is_owner || !context.actor_has_recent_aal2 {
        return Err(OwnerProtectionError::OwnerTargetProtected);
    }
    Ok(())
}

/// Map an actor and its computed owner status into the owner-target contract.
/// Machine actors never have human assurance and therefore fail by construction.
pub fn owner_target_context(
    actor: &ActorContext,
    target_is_owner: bool,
    actor_is_owner: bool,
    required_scope: ManagementScope,
    now: chrono::DateTime<chrono::Utc>,
    recent_ttl: Duration,
) -> OwnerTargetContext {
    let (actor_is_machine, actor_has_recent_aal2) = match &actor.principal {
        ActorPrincipal::User { authentication, .. } => {
            (false, authentication.is_recent_aal2(now, recent_ttl))
        }
        ActorPrincipal::Client { .. } => (true, false),
    };
    OwnerTargetContext {
        target_is_owner: target_is_owner && required_scope.is_owner_target_sensitive(),
        actor_is_owner,
        actor_is_machine,
        actor_has_recent_aal2,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        OwnerLifecycleContext, OwnerProtectionError, OwnerTargetContext,
        ensure_owner_target_allowed, ensure_usable_owner_survives, owner_target_context,
    };
    use crate::{
        authorization::{
            actor::{ActorContext, HumanAuthenticationContext, RequestId},
            catalog::ManagementScope,
        },
        user::UserOid,
    };

    #[test]
    fn last_usable_owner_cannot_be_removed() {
        assert_eq!(
            ensure_usable_owner_survives(OwnerLifecycleContext {
                target_was_active_owner: true,
                target_remains_active_owner: false,
                target_was_usable_owner: true,
                target_remains_usable_owner: false,
                other_active_owner_count: 0,
                other_usable_owner_count: 0,
            }),
            Err(OwnerProtectionError::LastOwnerProtected)
        );
        assert!(
            ensure_usable_owner_survives(OwnerLifecycleContext {
                target_was_active_owner: true,
                target_remains_active_owner: false,
                target_was_usable_owner: true,
                target_remains_usable_owner: false,
                other_active_owner_count: 1,
                other_usable_owner_count: 1,
            })
            .is_ok()
        );
        assert!(
            ensure_usable_owner_survives(OwnerLifecycleContext {
                target_was_active_owner: true,
                target_remains_active_owner: true,
                target_was_usable_owner: false,
                target_remains_usable_owner: false,
                other_active_owner_count: 1,
                other_usable_owner_count: 0,
            })
            .is_ok()
        );
        assert_eq!(
            ensure_usable_owner_survives(OwnerLifecycleContext {
                target_was_active_owner: true,
                target_remains_active_owner: false,
                target_was_usable_owner: false,
                target_remains_usable_owner: false,
                other_active_owner_count: 1,
                other_usable_owner_count: 0,
            }),
            Ok(())
        );
        assert_eq!(
            ensure_usable_owner_survives(OwnerLifecycleContext {
                target_was_active_owner: true,
                target_remains_active_owner: true,
                target_was_usable_owner: true,
                target_remains_usable_owner: false,
                other_active_owner_count: 1,
                other_usable_owner_count: 0,
            }),
            Err(OwnerProtectionError::LastOwnerProtected)
        );
    }

    #[test]
    fn owner_target_requires_a_human_owner_with_recent_aal2() {
        for context in [
            OwnerTargetContext {
                target_is_owner: true,
                actor_is_owner: false,
                actor_is_machine: false,
                actor_has_recent_aal2: true,
            },
            OwnerTargetContext {
                target_is_owner: true,
                actor_is_owner: true,
                actor_is_machine: true,
                actor_has_recent_aal2: true,
            },
            OwnerTargetContext {
                target_is_owner: true,
                actor_is_owner: true,
                actor_is_machine: false,
                actor_has_recent_aal2: false,
            },
        ] {
            assert_eq!(
                ensure_owner_target_allowed(context),
                Err(OwnerProtectionError::OwnerTargetProtected)
            );
        }
        assert!(
            ensure_owner_target_allowed(OwnerTargetContext {
                target_is_owner: true,
                actor_is_owner: true,
                actor_is_machine: false,
                actor_has_recent_aal2: true,
            })
            .is_ok()
        );
    }

    #[test]
    fn machine_actor_never_satisfies_owner_target_protection() {
        let actor =
            ActorContext::for_client(Uuid::new_v4(), RequestId::new("request-1").unwrap(), None);
        let context = owner_target_context(
            &actor,
            true,
            true,
            ManagementScope::CredentialsReset,
            Utc.timestamp_opt(1_000, 0).single().unwrap(),
            Duration::from_secs(300),
        );
        assert!(context.actor_is_machine);
        assert!(!context.actor_has_recent_aal2);
    }

    #[test]
    fn reader_scope_on_owner_is_not_treated_as_high_risk() {
        let actor = ActorContext::for_user(
            UserOid(Uuid::new_v4()),
            HumanAuthenticationContext::aal2(None),
            RequestId::new("request-1").unwrap(),
            None,
        );
        let context = owner_target_context(
            &actor,
            true,
            false,
            ManagementScope::UsersRead,
            Utc.timestamp_opt(1_000, 0).single().unwrap(),
            Duration::from_secs(300),
        );
        assert!(!context.target_is_owner);
        assert!(ensure_owner_target_allowed(context).is_ok());
    }
}
