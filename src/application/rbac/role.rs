//! Business Role management types.

use chrono::{DateTime, Utc};
use identity_domain::rbac::{LocalizedMetadata, LocalizedText, RoleOid};
use serde::Serialize;
use uuid::Uuid;

use super::model::ScopeOid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRecord {
    pub oid: RoleOid,
    /// Independent fallback name.
    pub name: String,
    /// Independent fallback description.
    pub description: String,
    pub built_in: bool,
    pub names: Vec<LocalizedText>,
    pub descriptions: Vec<LocalizedText>,
    pub enabled: bool,
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl RoleRecord {
    #[must_use]
    pub fn metadata(&self) -> LocalizedMetadata {
        LocalizedMetadata {
            names: self.names.clone(),
            descriptions: self.descriptions.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct RoleFilter {
    pub query: Option<String>,
    pub enabled: Option<bool>,
    pub built_in: Option<bool>,
    /// Restricts the list to roles that explicitly contain this scope.
    pub scope_oid: Option<ScopeOid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleOrder {
    CreatedAtAsc,
    CreatedAtDesc,
    NameAsc,
    NameDesc,
}

impl Default for RoleOrder {
    fn default() -> Self {
        Self::CreatedAtDesc
    }
}

impl RoleOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
            Self::NameAsc => 2,
            Self::NameDesc => 3,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreatedAtAsc),
            1 => Some(Self::CreatedAtDesc),
            2 => Some(Self::NameAsc),
            3 => Some(Self::NameDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc | Self::NameDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RolePageRequest {
    pub filter: RoleFilter,
    pub order: RoleOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RolePageItem {
    pub record: RoleRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct RolePage {
    pub items: Vec<RolePageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct CreateRoleCommand {
    /// Independent default name, required even when translations are supplied.
    pub name: String,
    pub description: String,
    pub metadata: Option<LocalizedMetadata>,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateRoleCommand {
    pub name: Option<String>,
    pub description: Option<String>,
    pub role_oid: RoleOid,
    /// Replaces the localized names only when supplied. Omission preserves the
    /// locked current names; an explicit empty list is invalid.
    pub names: Option<Vec<LocalizedText>>,
    /// Replaces the localized descriptions only when supplied. Omission
    /// preserves the locked current descriptions; an explicit empty list clears
    /// them.
    pub descriptions: Option<Vec<LocalizedText>>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RoleStateCommand {
    pub role_oid: RoleOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SetRolePermissionsCommand {
    pub role_oid: RoleOid,
    /// Role membership references canonical scope identities.
    pub scope_oids: Vec<ScopeOid>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}
