//! Instance settings and key management error catalog. Reserved range:
//! 29000-29099.
//!
//! Management authority, audit and step-up failures keep using the
//! authorization catalog; cursor and page-argument failures keep using the
//! shared business RBAC codes.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum InstanceErrorCode {
    VersionConflict = 29000,
    SettingOutOfRange = 29001,
    InvalidClientMutationId = 29002,
    StorageFailed = 29003,
    KeyNotFound = 29004,
    KeyNotCurrent = 29005,
    LastActiveKey = 29006,
    KeyAlreadyRevoked = 29007,
    UnsupportedKeyAlgorithm = 29008,
}

impl InstanceErrorCode {
    pub const fn kind(self) -> ErrorKind {
        match self {
            Self::KeyNotFound => ErrorKind::NotFound,
            Self::VersionConflict
            | Self::KeyNotCurrent
            | Self::LastActiveKey
            | Self::KeyAlreadyRevoked => ErrorKind::Conflict,
            Self::StorageFailed => ErrorKind::Internal,
            Self::SettingOutOfRange
            | Self::InvalidClientMutationId
            | Self::UnsupportedKeyAlgorithm => ErrorKind::Validation,
        }
    }
}

impl AppErrorCode for InstanceErrorCode {
    fn kind(self) -> ErrorKind {
        Self::kind(self)
    }

    fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceErrorCodeDefinition {
    pub code: InstanceErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const INSTANCE_ERROR_INVENTORY: &[InstanceErrorCodeDefinition] = &[
    entry(
        InstanceErrorCode::VersionConflict,
        "E29000",
        &[],
        &["current_version"],
    ),
    entry(
        InstanceErrorCode::SettingOutOfRange,
        "E29001",
        &["min", "max"],
        &[],
    ),
    entry(
        InstanceErrorCode::InvalidClientMutationId,
        "E29002",
        &["max"],
        &[],
    ),
    entry(InstanceErrorCode::StorageFailed, "E29003", &[], &[]),
    entry(InstanceErrorCode::KeyNotFound, "E29004", &[], &[]),
    entry(InstanceErrorCode::KeyNotCurrent, "E29005", &[], &[]),
    entry(InstanceErrorCode::LastActiveKey, "E29006", &[], &[]),
    entry(InstanceErrorCode::KeyAlreadyRevoked, "E29007", &[], &[]),
    entry(
        InstanceErrorCode::UnsupportedKeyAlgorithm,
        "E29008",
        &["algorithm"],
        &[],
    ),
];

const fn entry(
    code: InstanceErrorCode,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
) -> InstanceErrorCodeDefinition {
    InstanceErrorCodeDefinition {
        code,
        numeric_code: code as u32,
        kind: code.kind(),
        fluent_key,
        required_params,
        optional_params,
        usage_module: "instance",
    }
}
