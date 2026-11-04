//! Client API-scope delegation types over the canonical `client_scope` relation.
//!
//! This is not a fabricated `(client, resource, scopes)` grant. Replacement is
//! exact over resource-owned API scopes (built-in or custom) and leaves
//! protocol/identity assignments untouched.
//!
//! Every assignment bounds what the client may request on behalf of a user.
//! `client_granted` additionally grants the scope to the client itself, which
//! is what client-credentials access and machine principals use.

use identity_domain::client::model::ClientOid;
use serde::Serialize;
use uuid::Uuid;

use super::{
    model::ScopeOid,
    scope::{ScopeOrder, ScopeRecord},
};

/// One client API-scope assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientScopeAssignment {
    pub scope_oid: ScopeOid,
    /// The client itself holds this scope, not only users acting through it.
    pub client_granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientScopeTargetRecord {
    pub client_oid: ClientOid,
    pub name: String,
    pub built_in: bool,
    pub allowed_scope_count: i64,
    /// Live `client.version`; callers pass this as `expectedVersion` to
    /// `setClientScopes`.
    pub version: Uuid,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ClientScopeTargetFilter {
    pub query: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ClientScopeTargetOrder {
    #[default]
    NameAsc,
    NameDesc,
}

impl ClientScopeTargetOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::NameAsc => 0,
            Self::NameDesc => 1,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NameAsc),
            1 => Some(Self::NameDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::NameDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClientScopeTargetPageRequest {
    pub filter: ClientScopeTargetFilter,
    pub order: ClientScopeTargetOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientScopeTargetPageItem {
    pub record: ClientScopeTargetRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct ClientScopeTargetPage {
    pub items: Vec<ClientScopeTargetPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClientScopePageRequest {
    pub client_oid: ClientOid,
    pub order: ScopeOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientScopePageItem {
    pub record: ScopeRecord,
    pub client_granted: bool,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct ClientScopePage {
    pub items: Vec<ClientScopePageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct SetClientScopesCommand {
    pub client_oid: ClientOid,
    /// Exact, resource-owned API scope assignments. Protocol entries are
    /// rejected and existing protocol assignments are preserved.
    pub scopes: Vec<ClientScopeAssignment>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientScopeSetResult {
    pub client_oid: ClientOid,
    pub version: Uuid,
    pub scopes: Vec<ClientScopeAssignment>,
}
