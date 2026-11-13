//! Stable identifiers for unified RBAC.
//!
//! Each kind is a distinct type even though all are UUIDs, so a role, group,
//! membership or binding OID cannot be passed where another is expected.

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

uuid_oid!(ResourceOid);
uuid_oid!(ResourcePermissionOid);
uuid_oid!(RoleOid);
uuid_oid!(RolePermissionOid);
uuid_oid!(UserRoleOid);
uuid_oid!(GroupOid);
uuid_oid!(GroupMembershipOid);
uuid_oid!(GroupRoleOid);
