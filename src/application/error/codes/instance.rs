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
    EmailDeliveryNotConfigured = 29009,
    InvalidEmailTemplate = 29010,
    TestEmailFailed = 29011,
    EmailSettingRequired = 29012,
    InvalidEmailAddress = 29013,
    InvalidEmailTokenEndpoint = 29014,
    UnsupportedEmailLocale = 29015,
    EmailTemplateTooLong = 29016,
    DuplicateEmailLocale = 29017,
}

impl AppErrorCode for InstanceErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::KeyNotFound => ErrorKind::NotFound,
            Self::EmailDeliveryNotConfigured => ErrorKind::Conflict,
            Self::TestEmailFailed => ErrorKind::Internal,
            Self::InvalidEmailTemplate
            | Self::EmailSettingRequired
            | Self::InvalidEmailAddress
            | Self::InvalidEmailTokenEndpoint
            | Self::UnsupportedEmailLocale
            | Self::EmailTemplateTooLong
            | Self::DuplicateEmailLocale => ErrorKind::Validation,
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

    fn code(self) -> u32 {
        self as u32
    }

    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::SettingOutOfRange => &["min", "max"],
            Self::InvalidClientMutationId | Self::EmailTemplateTooLong => &["max"],
            Self::UnsupportedKeyAlgorithm => &["algorithm"],
            Self::InvalidEmailTemplate | Self::TestEmailFailed => &["detail"],
            Self::UnsupportedEmailLocale | Self::DuplicateEmailLocale => &["locale"],
            _ => &[],
        }
    }

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::VersionConflict => &["current_version"],
            _ => &[],
        }
    }
}
