//! Shared application values for unified RBAC management.
//!
//! Management authority is accepted as immutable request facts but is never
//! treated as proof. The repository re-loads authoritative state inside each
//! write transaction.

use std::{collections::BTreeSet, fmt, str::FromStr};

use identity_domain::{
    authorization::{
        ActorContext, ManagementAuthorizationSnapshot, ManagementScope, PolicyVersion,
    },
    client::model::ClientOid,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Immutable request authority accepted by every RBAC write.
///
/// The issuing client identity and the original client-authority fingerprint
/// are verified credential facts. The repository re-locks the live client and
/// policy, derives the fingerprint from the same transaction and compares it
/// before any grant/owner check; it never substitutes the current value or a
/// record optimistic-lock version into this value.
#[derive(Debug, Clone)]
pub struct RbacManagementAuthority {
    pub actor: ActorContext,
    pub token_scopes: BTreeSet<ManagementScope>,
    pub snapshot: Option<ManagementAuthorizationSnapshot>,
    pub client_oid: ClientOid,
    pub client_policy_version: PolicyVersion,
}

impl RbacManagementAuthority {
    #[must_use]
    pub fn new(
        actor: ActorContext,
        token_scopes: BTreeSet<ManagementScope>,
        snapshot: Option<ManagementAuthorizationSnapshot>,
        client_oid: ClientOid,
        client_policy_version: PolicyVersion,
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

/// Typed OID for one global scope catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeOid(pub Uuid);

impl ScopeOid {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ScopeOid {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ScopeOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<ScopeOid> for Uuid {
    fn from(value: ScopeOid) -> Self {
        value.0
    }
}

impl fmt::Display for ScopeOid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for ScopeOid {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// One localized scope name or description entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDescription {
    pub locale: String,
    pub value: String,
}

pub(crate) const DEFAULT_PAGE_SIZE: u32 = 20;
pub(crate) const MAX_PAGE_SIZE: u32 = 100;
pub(crate) const MAX_REASON_LENGTH: usize = 1_000;
pub(crate) const MAX_CLIENT_MUTATION_ID_LENGTH: usize = 255;
pub(crate) const MAX_QUERY_FILTER_LENGTH: usize = 255;
pub(crate) const MAX_DISPLAY_NAME_LENGTH: usize = 256;
pub(crate) const MAX_DESCRIPTION_LENGTH: usize = 1_024;
pub(crate) const MAX_ROLE_PERMISSIONS: usize = 1_000;
pub(crate) const MAX_USER_ROLES: usize = 100;
pub(crate) const MAX_BINDING_LOOKUPS: usize = 100;
pub(crate) const MAX_SCOPE_ASSIGNMENTS: usize = 1_000;
pub(crate) const MAX_DESCRIPTION_LOCALES: usize = 20;
