//! API resource management types.

use chrono::{DateTime, Utc};
use identity_domain::rbac::ResourceOid;
use serde::Serialize;
use uuid::Uuid;

/// One API resource plus its own UUID optimistic-lock version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResourceRecord {
    pub oid: ResourceOid,
    pub uri: String,
    pub name: String,
    pub enabled: bool,
    /// Read-only projection derived from scope rows owned by this resource.
    pub accepted_scopes: Vec<String>,
    /// `resource.version`; UUID optimistic lock.
    pub version: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceFilter {
    pub query: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ResourceOrder {
    CreatedAtAsc,
    #[default]
    CreatedAtDesc,
    NameAsc,
    NameDesc,
    UriAsc,
    UriDesc,
}

impl ResourceOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
            Self::NameAsc => 2,
            Self::NameDesc => 3,
            Self::UriAsc => 4,
            Self::UriDesc => 5,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreatedAtAsc),
            1 => Some(Self::CreatedAtDesc),
            2 => Some(Self::NameAsc),
            3 => Some(Self::NameDesc),
            4 => Some(Self::UriAsc),
            5 => Some(Self::UriDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc | Self::NameDesc | Self::UriDesc)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResourcePageRequest {
    pub filter: ResourceFilter,
    pub order: ResourceOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResourcePageItem {
    pub record: ApiResourceRecord,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct ResourcePage {
    pub items: Vec<ResourcePageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct CreateResourceCommand {
    pub uri: String,
    pub name: String,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateResourceCommand {
    pub resource_oid: ResourceOid,
    pub name: Option<String>,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResourceStateCommand {
    pub resource_oid: ResourceOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}
