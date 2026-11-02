//! Global scope catalog management types.

use chrono::{DateTime, Utc};
use identity_domain::rbac::{ResourceOid, RoleOid};
use serde::Serialize;
use uuid::Uuid;

use super::model::{ScopeDescription, ScopeOid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRecord {
    pub oid: ScopeOid,
    /// Owning API resource. `None` marks a protocol/identity scope.
    pub resource_oid: Option<ResourceOid>,
    /// Stable machine token used in protocol requests and assignments.
    pub code: String,
    /// Independent fallback name.
    pub name: String,
    pub names: Vec<ScopeDescription>,
    /// Independent fallback description.
    pub description: String,
    pub descriptions: Vec<ScopeDescription>,
    pub built_in: bool,
    pub enabled: bool,
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeFilter {
    /// Case-insensitive literal substring of the scope code only.
    pub query: Option<String>,
    pub built_in: Option<bool>,
    pub enabled: Option<bool>,
    /// Direct `scope.resource_id` ownership filter.
    pub resource_oid: Option<ResourceOid>,
    /// Roles that explicitly contain this scope.
    pub role_oid: Option<RoleOid>,
    /// Restrict to concrete, resource-owned API scopes. Excludes protocol scopes
    /// and wildcard selector definitions.
    pub api_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeOrder {
    CreatedAtAsc,
    CreatedAtDesc,
    CodeAsc,
    CodeDesc,
}

impl Default for ScopeOrder {
    fn default() -> Self {
        Self::CreatedAtDesc
    }
}

impl ScopeOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
            Self::CodeAsc => 2,
            Self::CodeDesc => 3,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreatedAtAsc),
            1 => Some(Self::CreatedAtDesc),
            2 => Some(Self::CodeAsc),
            3 => Some(Self::CodeDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc | Self::CodeDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScopePageRequest {
    pub filter: ScopeFilter,
    pub order: ScopeOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScopePageItem {
    pub record: ScopeRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct ScopePage {
    pub items: Vec<ScopePageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct CreateScopeCommand {
    /// Every custom scope is owned by an API resource.
    pub resource_oid: ResourceOid,
    pub code: String,
    pub name: String,
    pub names: Vec<ScopeDescription>,
    pub description: String,
    pub descriptions: Vec<ScopeDescription>,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScopeStateCommand {
    pub scope_oid: ScopeOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateScopeCommand {
    pub scope_oid: ScopeOid,
    pub name: Option<String>,
    pub names: Option<Vec<ScopeDescription>>,
    pub description: Option<String>,
    pub descriptions: Option<Vec<ScopeDescription>>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}
