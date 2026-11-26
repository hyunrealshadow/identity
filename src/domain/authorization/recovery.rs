//! Recoverability facts collected within the authorization-changing transaction.

/// Snapshot of owner recovery facts. Collection must happen inside the same
/// transaction that changes bindings/credentials/account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerAccessSnapshot {
    pub target_user_enabled: bool,
    pub target_has_recoverable_credential: bool,
    pub target_is_active_owner: bool,
    pub other_active_owner_count: u64,
    pub other_usable_owner_count: u64,
}

impl OwnerAccessSnapshot {
    #[must_use]
    pub fn target_is_usable_owner(&self) -> bool {
        self.target_is_active_owner
            && self.target_user_enabled
            && self.target_has_recoverable_credential
    }
}
