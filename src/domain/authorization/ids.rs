//! Stable identities and opaque UUID values for management authorization.
//!
//! Display names, role names, array positions and user/client supplied strings
//! are never identities. Grant records own stable OIDs and independent UUID
//! optimistic locks. Snapshots use derived semantic fingerprints; permanent
//! withdrawal prevents old credentials reviving after authority is restored.

use std::fmt;

use uuid::Uuid;

macro_rules! uuid_oid {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

uuid_oid!(AdministratorBindingOid);

/// Opaque UUID value used by authorization domain ports.
///
/// A persisted grant's `version` is a random optimistic-lock token only.
/// Authority fields instead receive deterministic semantic fingerprints via
/// `from_uuid`; they never copy a record optimistic lock. Neither value is a
/// counter, and fingerprint equality cannot clear a permanent withdrawal.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct AuthorizationVersion(pub Uuid);

impl AuthorizationVersion {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Fresh record optimistic lock. Equivalent to [`Self::new`].
    #[must_use]
    pub fn fresh() -> Self {
        Self::new()
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for AuthorizationVersion {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AuthorizationVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<Uuid> for AuthorizationVersion {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<AuthorizationVersion> for Uuid {
    fn from(value: AuthorizationVersion) -> Self {
        value.0
    }
}

/// Opaque fingerprint of the trusted authorization policy/catalog semantics.
///
/// This wrapper carries deterministic catalog or client-security semantics;
/// it is not a mutable state-row version, counter or optimistic-lock token.
/// Snapshots bind to it so a semantic policy change cannot silently reinterpret
/// an old grant. Display text, translations, usage/cache metadata and database
/// record versions never participate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct PolicyVersion(pub Uuid);

impl PolicyVersion {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn fresh() -> Self {
        Self::new()
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for PolicyVersion {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<Uuid> for PolicyVersion {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<PolicyVersion> for Uuid {
    fn from(value: PolicyVersion) -> Self {
        value.0
    }
}
