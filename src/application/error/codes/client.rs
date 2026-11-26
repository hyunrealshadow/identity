//! OAuth client management error catalog. Reserved range: 18000-18099.
//!
//! Cursor and page-argument failures keep using the shared business RBAC codes
//! (17037/17038/17039); management authority and audit failures keep using the
//! authorization catalog. Every client-specific failure is defined here.

define_error_codes! {
    pub enum ClientErrorCode(module = "client") {
        ValidationFailed = 18000 { kind: Validation, optional: [field] },
        ClientNotFound = 18001 { kind: NotFound },
        CredentialNotFound = 18002 { kind: NotFound },
        VersionConflict = 18003 { kind: Conflict, required: [current_version] },
        BuiltInProtected = 18004 { kind: Forbidden },
        InvalidName = 18005 { kind: Validation, optional: [max] },
        InvalidDescription = 18006 { kind: Validation, required: [max] },
        InvalidLocale = 18007 { kind: Validation, required: [max] },
        DuplicateLocale = 18008 { kind: Validation, required: [locale] },
        InvalidRedirectUri = 18009 { kind: Validation, required: [uri] },
        InvalidPostLogoutRedirectUri = 18010 { kind: Validation, required: [uri] },
        DuplicatePlatform = 18011 { kind: Validation, required: [platform] },
        InvalidGrantTypes = 18012 { kind: Validation },
        UnsupportedGrantType = 18013 { kind: Validation, required: [grant_type] },
        RedirectUriRequired = 18015 { kind: Validation },
        RefreshTokenRequiresInteractiveGrant = 18017 { kind: Validation },
        CredentialNotSecret = 18018 { kind: Validation },
        CredentialRevoked = 18019 { kind: Conflict },
        InvalidSecretLifetime = 18021 { kind: Validation, required: [min, max] },
        InvalidFilter = 18022 { kind: Validation, required: [max] },
        InvalidReason = 18023 { kind: Validation, required: [max] },
        InvalidClientMutationId = 18024 { kind: Validation, required: [max] },
        EmptyUpdate = 18025 { kind: Validation },
        InvalidCollectionSize = 18026 { kind: Validation, required: [max] },
        StorageFailed = 18027 { kind: Internal },
        InvalidPublicKey = 18028 { kind: Validation },
        PrivateKeyNotAccepted = 18029 { kind: Validation },
        CertificateExpired = 18030 { kind: Validation },
        PublicKeyExpiryRequired = 18031 { kind: Validation },
        InvalidCredentialExpiry = 18032 { kind: Validation, required: [min, max] },
        InvalidJwksUri = 18033 { kind: Validation },
        JwksUnavailable = 18034 { kind: Validation },
        CredentialLimitReached = 18035 { kind: Validation, required: [max] },
        InvalidMetadataUri = 18036 { kind: Validation, required: [uri] },
        InvalidContact = 18037 { kind: Validation, required: [max] },
        UnsupportedAlgorithm = 18038 { kind: Validation, required: [algorithm] },
        EncryptionAlgorithmRequired = 18039 { kind: Validation },
        LogoutUriRequired = 18040 { kind: Validation },
        InvalidDefaultMaxAge = 18041 { kind: Validation, required: [max] },
        UnsupportedAcrValue = 18042 { kind: Validation, required: [acr] },
        SectorIdentifierRequired = 18043 { kind: Validation },
        SectorIdentifierMismatch = 18044 { kind: Validation },
        SectorIdentifierUnavailable = 18045 { kind: Validation },
    }
}
