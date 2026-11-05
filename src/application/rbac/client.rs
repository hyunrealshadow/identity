//! Client scope assignment types over the canonical `client_scope` relation.
//!
//! This is not a fabricated `(client, resource, scopes)` grant. Replacement is
//! exact over every assigned scope: resource-owned API scopes (built-in or
//! custom) and protocol/identity scopes such as `openid`.
//!
//! Every assignment bounds what the client may request on behalf of a user.
//! `client_granted` additionally grants the scope to the client itself, which
//! is what client-credentials access and machine principals use.

use identity_domain::client::model::ClientOid;
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
    /// The complete assignment set. Protocol entries never set
    /// `client_granted`.
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
