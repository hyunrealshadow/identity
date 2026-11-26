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
    InvalidMetadataUri = 18036,
    InvalidContact = 18037,
    UnsupportedAlgorithm = 18038,
    EncryptionAlgorithmRequired = 18039,
    LogoutUriRequired = 18040,
    InvalidDefaultMaxAge = 18041,
    UnsupportedAcrValue = 18042,
    SectorIdentifierRequired = 18043,
    SectorIdentifierMismatch = 18044,
    SectorIdentifierUnavailable = 18045,
}

impl AppErrorCode for ClientErrorCode {
    fn kind(self) -> ErrorKind {
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
            | Self::CredentialLimitReached
            | Self::InvalidMetadataUri
            | Self::InvalidContact
            | Self::UnsupportedAlgorithm
            | Self::EncryptionAlgorithmRequired
            | Self::LogoutUriRequired
            | Self::InvalidDefaultMaxAge
            | Self::UnsupportedAcrValue
            | Self::SectorIdentifierRequired
            | Self::SectorIdentifierMismatch
            | Self::SectorIdentifierUnavailable => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        self as u32
    }

    fn required_params(self) -> &'static [&'static str] {
        match self {
            Self::VersionConflict => &["current_version"],
            Self::InvalidDescription
            | Self::InvalidLocale
            | Self::InvalidFilter
            | Self::InvalidReason
            | Self::InvalidClientMutationId
            | Self::InvalidCollectionSize
            | Self::CredentialLimitReached
            | Self::InvalidContact
            | Self::InvalidDefaultMaxAge => &["max"],
            Self::DuplicateLocale => &["locale"],
            Self::InvalidRedirectUri
            | Self::InvalidPostLogoutRedirectUri
            | Self::InvalidMetadataUri => &["uri"],
            Self::DuplicatePlatform => &["platform"],
            Self::UnsupportedGrantType => &["grant_type"],
            Self::InvalidSecretLifetime | Self::InvalidCredentialExpiry => &["min", "max"],
            Self::UnsupportedAlgorithm => &["algorithm"],
            Self::UnsupportedAcrValue => &["acr"],
            _ => &[],
        }
    }

    fn optional_params(self) -> &'static [&'static str] {
        match self {
            Self::ValidationFailed => &["field"],
            Self::InvalidName => &["max"],
            _ => &[],
        }
    }
}
