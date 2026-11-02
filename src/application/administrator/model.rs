//! Public command, context and page types for instance administrator management.
//!
//! The GraphQL adapter validates InputObjects and decodes Global IDs before it
//! constructs these values. The application service re-validates reason, page
//! and filter bounds and the transactional repository re-loads authoritative
//! state inside the write transaction.

use std::collections::BTreeSet;

use identity_domain::{
    authorization::{
        ActorContext, AdministratorBinding, AdministratorBindingOid, AdministratorRole,
        AuthorizationVersion, ManagementAuthorizationSnapshot, ManagementScope,
    },
    client::model::ClientOid,
    user::UserOid,
};

pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_QUERY_FILTER_LENGTH: usize = 255;
pub const MAX_REASON_LENGTH: usize = 1_000;

/// Immutable request authority accepted by every write method.
///
/// `client_oid` is the OAuth client that issued the access token and
/// `client_policy_version` is the derived client-authority fingerprint that
/// credential observed. The repository re-locks the issuing client and its
/// management policy, derives the current fingerprint, reloads the actor's live
/// authority and checks the exact snapshot inside the mutation transaction.
/// This value is never proof by itself and is never compared to the client
/// record's optimistic-lock version.
#[derive(Debug, Clone)]
pub struct AdministratorManagementAuthority {
    pub actor: ActorContext,
    pub token_scopes: BTreeSet<ManagementScope>,
    pub snapshot: Option<ManagementAuthorizationSnapshot>,
    pub client_oid: ClientOid,
    pub client_policy_version: identity_domain::authorization::PolicyVersion,
}

impl AdministratorManagementAuthority {
    #[must_use]
    pub fn new(
        actor: ActorContext,
        token_scopes: BTreeSet<ManagementScope>,
        snapshot: Option<ManagementAuthorizationSnapshot>,
        client_oid: ClientOid,
        client_policy_version: identity_domain::authorization::PolicyVersion,
    ) -> Self {
        Self {
            actor,
            token_scopes,
            snapshot,
            client_oid,
            client_policy_version,
        }
    }
}

/// Instance administrator directory filter. Strings are free-form and are
/// treated literally, never as SQL wildcards.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AdministratorFilter {
    pub query: Option<String>,
    pub role: Option<AdministratorRole>,
    pub enabled: Option<bool>,
    pub user_oid: Option<UserOid>,
}

/// Stable administrator directory order. Newest first is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdministratorOrder {
    CreatedAtAsc,
    CreatedAtDesc,
}

impl Default for AdministratorOrder {
    fn default() -> Self {
        Self::CreatedAtDesc
    }
}

impl AdministratorOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreatedAtAsc),
            1 => Some(Self::CreatedAtDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc)
    }
}

/// Relay-style page request. `first`/`last` accept 1..=100 and default to 20.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AdministratorPageRequest {
    pub filter: AdministratorFilter,
    pub order: AdministratorOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

/// One directory row plus its protected, filter-bound cursor.
#[derive(Debug, Clone)]
pub struct AdministratorPageItem {
    pub binding: AdministratorBinding,
    pub cursor: String,
}

/// Relay-style administrator page with accurate boundary flags.
#[derive(Debug, Clone)]
pub struct AdministratorPage {
    pub items: Vec<AdministratorPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct AssignAdministratorCommand {
    pub user_oid: UserOid,
    pub role: AdministratorRole,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct UpdateAdministratorRoleCommand {
    pub binding_oid: AdministratorBindingOid,
    pub role: AdministratorRole,
    pub expected_version: AuthorizationVersion,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RevokeAdministratorCommand {
    pub binding_oid: AdministratorBindingOid,
    pub expected_version: AuthorizationVersion,
    pub reason: String,
}
