//! OAuth client management error catalog. Reserved range: 18000-18099.
//!
//! Cursor and page-argument failures keep using the shared business RBAC codes
//! (17037/17038/17039); management authority and audit failures keep using the
//! authorization catalog. Every client-specific failure is defined here.

use crate::error::{code::AppErrorCode, kind::ErrorKind};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum ClientErrorCode {
    ValidationFailed = 18000,
    ClientNotFound = 18001,
    CredentialNotFound = 18002,
    VersionConflict = 18003,
    BuiltInProtected = 18004,
    InvalidName = 18005,
    InvalidDescription = 18006,
    InvalidLocale = 18007,
    DuplicateLocale = 18008,
    InvalidRedirectUri = 18009,
    InvalidPostLogoutRedirectUri = 18010,
    DuplicatePlatform = 18011,
    InvalidGrantTypes = 18012,
    UnsupportedGrantType = 18013,
    RedirectUriRequired = 18015,
    RefreshTokenRequiresInteractiveGrant = 18017,
    CredentialNotSecret = 18018,
    CredentialRevoked = 18019,
    InvalidSecretLifetime = 18021,
    InvalidFilter = 18022,
    InvalidReason = 18023,
    InvalidClientMutationId = 18024,
    EmptyUpdate = 18025,
    InvalidCollectionSize = 18026,
    StorageFailed = 18027,
    InvalidPublicKey = 18028,
    PrivateKeyNotAccepted = 18029,
    CertificateExpired = 18030,
    PublicKeyExpiryRequired = 18031,
    InvalidCredentialExpiry = 18032,
    InvalidJwksUri = 18033,
    JwksUnavailable = 18034,
    CredentialLimitReached = 18035,
}

impl ClientErrorCode {
    pub const fn kind(self) -> ErrorKind {
        match self {
            Self::ClientNotFound | Self::CredentialNotFound => ErrorKind::NotFound,
            Self::VersionConflict | Self::CredentialRevoked => ErrorKind::Conflict,
            Self::BuiltInProtected => ErrorKind::Forbidden,
            Self::StorageFailed => ErrorKind::Internal,
            Self::ValidationFailed
            | Self::InvalidName
            | Self::InvalidDescription
            | Self::InvalidLocale
            | Self::DuplicateLocale
            | Self::InvalidRedirectUri
            | Self::InvalidPostLogoutRedirectUri
            | Self::DuplicatePlatform
            | Self::InvalidGrantTypes
            | Self::UnsupportedGrantType
            | Self::RedirectUriRequired
            | Self::RefreshTokenRequiresInteractiveGrant
            | Self::CredentialNotSecret
            | Self::InvalidSecretLifetime
            | Self::InvalidFilter
            | Self::InvalidReason
            | Self::InvalidClientMutationId
            | Self::EmptyUpdate
            | Self::InvalidCollectionSize
            | Self::InvalidPublicKey
            | Self::PrivateKeyNotAccepted
            | Self::CertificateExpired
            | Self::PublicKeyExpiryRequired
            | Self::InvalidCredentialExpiry
            | Self::InvalidJwksUri
            | Self::JwksUnavailable
            | Self::CredentialLimitReached => ErrorKind::Validation,
        }
    }
}

impl AppErrorCode for ClientErrorCode {
    fn kind(self) -> ErrorKind {
        Self::kind(self)
    }

    fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientErrorCodeDefinition {
    pub code: ClientErrorCode,
    pub numeric_code: u32,
    pub kind: ErrorKind,
    pub fluent_key: &'static str,
    pub required_params: &'static [&'static str],
    pub optional_params: &'static [&'static str],
    pub usage_module: &'static str,
}

pub const CLIENT_ERROR_INVENTORY: &[ClientErrorCodeDefinition] = &[
    entry(ClientErrorCode::ValidationFailed, "E18000", &[], &["field"]),
    entry(ClientErrorCode::ClientNotFound, "E18001", &[], &[]),
    entry(ClientErrorCode::CredentialNotFound, "E18002", &[], &[]),
    entry(
        ClientErrorCode::VersionConflict,
        "E18003",
        &["current_version"],
        &[],
    ),
    entry(ClientErrorCode::BuiltInProtected, "E18004", &[], &[]),
    entry(ClientErrorCode::InvalidName, "E18005", &[], &["max"]),
    entry(ClientErrorCode::InvalidDescription, "E18006", &["max"], &[]),
    entry(ClientErrorCode::InvalidLocale, "E18007", &["max"], &[]),
    entry(ClientErrorCode::DuplicateLocale, "E18008", &["locale"], &[]),
    entry(ClientErrorCode::InvalidRedirectUri, "E18009", &["uri"], &[]),
    entry(
        ClientErrorCode::InvalidPostLogoutRedirectUri,
        "E18010",
        &["uri"],
        &[],
    ),
    entry(
        ClientErrorCode::DuplicatePlatform,
        "E18011",
        &["platform"],
        &[],
    ),
    entry(ClientErrorCode::InvalidGrantTypes, "E18012", &[], &[]),
    entry(
        ClientErrorCode::UnsupportedGrantType,
        "E18013",
        &["grant_type"],
        &[],
    ),
    entry(ClientErrorCode::RedirectUriRequired, "E18015", &[], &[]),
    entry(
        ClientErrorCode::RefreshTokenRequiresInteractiveGrant,
        "E18017",
        &[],
        &[],
    ),
    entry(ClientErrorCode::CredentialNotSecret, "E18018", &[], &[]),
    entry(ClientErrorCode::CredentialRevoked, "E18019", &[], &[]),
    entry(
        ClientErrorCode::InvalidSecretLifetime,
        "E18021",
        &["min", "max"],
        &[],
    ),
    entry(ClientErrorCode::InvalidFilter, "E18022", &["max"], &[]),
    entry(ClientErrorCode::InvalidReason, "E18023", &["max"], &[]),
    entry(
        ClientErrorCode::InvalidClientMutationId,
        "E18024",
        &["max"],
        &[],
    ),
    entry(ClientErrorCode::EmptyUpdate, "E18025", &[], &[]),
    entry(
        ClientErrorCode::InvalidCollectionSize,
        "E18026",
        &["max"],
        &[],
    ),
    entry(ClientErrorCode::StorageFailed, "E18027", &[], &[]),
    entry(ClientErrorCode::InvalidPublicKey, "E18028", &[], &[]),
    entry(ClientErrorCode::PrivateKeyNotAccepted, "E18029", &[], &[]),
    entry(ClientErrorCode::CertificateExpired, "E18030", &[], &[]),
    entry(ClientErrorCode::PublicKeyExpiryRequired, "E18031", &[], &[]),
    entry(
        ClientErrorCode::InvalidCredentialExpiry,
        "E18032",
        &["min", "max"],
        &[],
    ),
    entry(ClientErrorCode::InvalidJwksUri, "E18033", &[], &[]),
    entry(ClientErrorCode::JwksUnavailable, "E18034", &[], &[]),
    entry(
        ClientErrorCode::CredentialLimitReached,
        "E18035",
        &["max"],
        &[],
    ),
];

const fn entry(
    code: ClientErrorCode,
    fluent_key: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
) -> ClientErrorCodeDefinition {
    ClientErrorCodeDefinition {
        code,
        numeric_code: code as u32,
        kind: code.kind(),
        fluent_key,
        required_params,
        optional_params,
        usage_module: "client",
    }
}

#[must_use]
pub fn inventory() -> &'static [ClientErrorCodeDefinition] {
    CLIENT_ERROR_INVENTORY
}
