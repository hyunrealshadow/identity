//! User-group management error catalog. Reserved range: 19000-19099.
//!
//! Cursor and page-argument failures keep using the shared business RBAC codes
//! (17037/17038/17039); every group-specific failure is defined here.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum GroupErrorCode {
    ValidationFailed = 19000,
    GroupNotFound = 19001,
    MembershipNotFound = 19002,
    RoleBindingNotFound = 19003,
    VersionConflict = 19004,
    InvalidName = 19006,
    InvalidDescription = 19007,
    InvalidLocale = 19008,
    BuiltInProtected = 19010,
    Disabled = 19011,
    InvalidReason = 19012,
    InvalidVersion = 19013,
    InvalidClientMutationId = 19014,
    EmptyUpdate = 19015,
    InvalidCollectionSize = 19016,
    RoleNotFound = 19017,
    RoleDisabled = 19018,
    DelegationCeilingExceeded = 19019,
    MembershipAlreadyActive = 19020,
    MembershipNotActive = 19021,
    StorageFailed = 19022,
    InvalidFilter = 19025,
    UserNotFound = 19026,
    InvalidMetadata = 19027,
    DuplicateLocale = 19028,
    NameRequired = 19029,
}

impl AppErrorCode for GroupErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::GroupNotFound
            | Self::MembershipNotFound
            | Self::RoleBindingNotFound
            | Self::RoleNotFound
            | Self::UserNotFound => ErrorKind::NotFound,

            Self::VersionConflict
            | Self::Disabled
            | Self::RoleDisabled
            | Self::MembershipAlreadyActive
            | Self::MembershipNotActive => ErrorKind::Conflict,

            Self::BuiltInProtected | Self::DelegationCeilingExceeded => ErrorKind::Forbidden,

            Self::StorageFailed => ErrorKind::Internal,

            Self::ValidationFailed
            | Self::InvalidName
            | Self::InvalidDescription
            | Self::InvalidLocale
            | Self::InvalidReason
            | Self::InvalidVersion
            | Self::InvalidClientMutationId
            | Self::EmptyUpdate
            | Self::InvalidCollectionSize
            | Self::InvalidFilter
            | Self::InvalidMetadata
            | Self::DuplicateLocale
            | Self::NameRequired => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        self as u32
    }

    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::VersionConflict => &["current_version"],
            Self::InvalidReason | Self::InvalidClientMutationId | Self::InvalidCollectionSize => {
                &["max"]
            }
            Self::DelegationCeilingExceeded => &["scope"],
            Self::InvalidFilter | Self::InvalidMetadata => &["field"],
            _ => &[],
        }
    }

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::ValidationFailed => &["field"],
            Self::InvalidName
            | Self::InvalidDescription
            | Self::InvalidLocale
            | Self::InvalidFilter => &["max"],
            Self::BuiltInProtected => &["key"],
            Self::DuplicateLocale => &["locale"],
            _ => &[],
        }
    }

    fn usage_module(self) -> Option<&'static str> {
        match self {
            Self::MembershipNotFound
            | Self::Disabled
            | Self::MembershipAlreadyActive
            | Self::MembershipNotActive
            | Self::UserNotFound => Some("rbac.group.membership"),
            Self::RoleBindingNotFound | Self::RoleNotFound | Self::RoleDisabled => {
                Some("rbac.group.roles")
            }
            Self::DelegationCeilingExceeded => Some("rbac.group.delegation"),
            Self::ValidationFailed
            | Self::GroupNotFound
            | Self::VersionConflict
            | Self::InvalidName
            | Self::InvalidDescription
            | Self::InvalidLocale
            | Self::BuiltInProtected
            | Self::InvalidReason
            | Self::InvalidVersion
            | Self::InvalidClientMutationId
            | Self::EmptyUpdate
            | Self::InvalidCollectionSize
            | Self::StorageFailed
            | Self::InvalidFilter
            | Self::InvalidMetadata
            | Self::DuplicateLocale
            | Self::NameRequired => None,
        }
    }
}
