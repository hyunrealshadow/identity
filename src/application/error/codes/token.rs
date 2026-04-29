use crate::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for `TokenService` and the `/oauth2/token` HTTP endpoint.
/// Range: 24000-24099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenErrorCode {
    // --- grant routing ---
    /// `grant_type` is not supported by this endpoint.
    UnsupportedGrantType,
    /// `client_id` parameter is missing from the request.
    ClientIdRequired,

    // --- authorization code exchange ---
    /// Database lookup for the authorization code record failed.
    CodeLookupFailed,
    /// Authorization code was not found.
    AuthCodeNotFound,
    /// Authorization code does not belong to the authenticated client.
    CodeClientMismatch,
    /// Authorization code is revoked or expired.
    AuthCodeInvalid,
    /// Failed to deserialize stored `AuthorizationCodeData`.
    DeserializeCodeFailed,
    /// `redirect_uri` does not match the one stored in the authorization code.
    RedirectUriMismatch,
    /// `code_verifier` is required but missing.
    CodeVerifierRequired,
    /// Stored `user_oid` in the authorization code is not a valid UUID.
    StoredUserOidInvalid,
    /// Database lookup for the user referenced by the authorization code failed.
    UserLookupFailed,
    /// User referenced by the authorization code was not found.
    AuthCodeUserNotFound,
    /// Database revocation of the used authorization code failed.
    RevokeCodeFailed,

    // --- refresh token exchange ---
    /// Database lookup for the refresh token record failed.
    RefreshTokenLookupFailed,
    /// Refresh token was not found.
    RefreshTokenNotFound,
    /// Refresh token is revoked or expired.
    RefreshTokenInvalid,
    /// Failed to deserialize stored `RefreshTokenData`.
    DeserializeRefreshFailed,
    /// Refresh token JWT is missing the `sub` claim.
    RefreshTokenSubMissing,
    /// Refresh token JWT is missing the `token_use` claim.
    RefreshTokenUseMissing,
    /// Refresh token `token_use` claim is not `"refresh_token"`.
    RefreshTokenUseInvalid,
    /// Refresh token does not belong to the authenticated client.
    RefreshTokenClientMismatch,
    /// Refresh token `sub` claim is not a valid UUID.
    RefreshTokenSubInvalid,
    /// User referenced by the refresh token was not found.
    RefreshTokenUserNotFound,
    /// Database revocation of the old refresh token failed.
    RevokeRefreshFailed,

    // --- signing key ---
    /// Database call to list available asymmetric signing keys failed.
    KeyListFailed,
    /// No RS256-capable signing key is available.
    NoSigningKeyAvailable,

    // --- client authentication ---
    /// `client_id` is not a valid UUID.
    ClientIdInvalid,
    /// Client was not found.
    ClientNotFound,
    /// Database call to find client failed.
    ClientLookupFailed,
    /// Database call to find client credentials failed.
    CredentialLookupFailed,
    /// Client secret does not match any stored credential.
    ClientCredentialsInvalid,
    /// No client authentication was provided.
    ClientAuthRequired,

    // --- private key JWT client assertion ---
    /// Client assertion JWT is missing the `iss` claim.
    AssertionIssMissing,
    /// Client assertion JWT is missing the `sub` claim.
    AssertionSubMissing,
    /// Assertion `iss`/`sub` do not equal `client_id`.
    AssertionIssSubMismatch,
    /// Assertion `aud` does not include the issuer URL.
    AssertionAudMismatch,
    /// Client assertion JWT has expired.
    AssertionExpired,
    /// Client assertion JWT `nbf` is in the future.
    AssertionNotYetValid,
    /// Failed to decode the client assertion JWT header.
    AssertionHeaderInvalid,
    /// Failed to verify the client assertion signature.
    AssertionVerifyFailed,
    /// Client assertion signing algorithm is not supported.
    AssertionAlgUnsupported,
    /// PEM public key for the client assertion is invalid.
    AssertionKeyInvalid,

    // --- refresh token verification ---
    /// No key could verify the refresh token JWT.
    RefreshTokenVerifyFailed,

    // --- token signing ---
    /// Failed to build or sign the access token JWT.
    SignAccessTokenFailed,
    /// Failed to build or sign the ID token JWT.
    SignIdTokenFailed,
    /// Failed to build or sign the refresh token JWT.
    SignRefreshTokenFailed,

    // --- refresh token storage ---
    /// Failed to serialize `RefreshTokenData`.
    SerializeRefreshFailed,
    /// Database write of the refresh token record failed.
    StoreRefreshFailed,

    // --- PKCE ---
    /// `code_challenge_method` is not `plain` or `S256`.
    PkceMethodUnsupported,
    /// `code_verifier` does not match the stored `code_challenge`.
    PkceVerifierMismatch,
}

impl AppErrorCode for TokenErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::UnsupportedGrantType => ErrorKind::Validation,
            Self::ClientIdRequired => ErrorKind::Validation,
            Self::CodeLookupFailed => ErrorKind::Internal,
            Self::AuthCodeNotFound => ErrorKind::Validation,
            Self::CodeClientMismatch => ErrorKind::Validation,
            Self::AuthCodeInvalid => ErrorKind::Validation,
            Self::DeserializeCodeFailed => ErrorKind::Internal,
            Self::RedirectUriMismatch => ErrorKind::Validation,
            Self::CodeVerifierRequired => ErrorKind::Validation,
            Self::StoredUserOidInvalid => ErrorKind::Internal,
            Self::UserLookupFailed => ErrorKind::Internal,
            Self::AuthCodeUserNotFound => ErrorKind::Validation,
            Self::RevokeCodeFailed => ErrorKind::Internal,
            Self::RefreshTokenLookupFailed => ErrorKind::Internal,
            Self::RefreshTokenNotFound => ErrorKind::Validation,
            Self::RefreshTokenInvalid => ErrorKind::Validation,
            Self::DeserializeRefreshFailed => ErrorKind::Internal,
            Self::RefreshTokenSubMissing => ErrorKind::Validation,
            Self::RefreshTokenUseMissing => ErrorKind::Validation,
            Self::RefreshTokenUseInvalid => ErrorKind::Validation,
            Self::RefreshTokenClientMismatch => ErrorKind::Validation,
            Self::RefreshTokenSubInvalid => ErrorKind::Validation,
            Self::RefreshTokenUserNotFound => ErrorKind::Validation,
            Self::RevokeRefreshFailed => ErrorKind::Internal,
            Self::KeyListFailed => ErrorKind::Internal,
            Self::NoSigningKeyAvailable => ErrorKind::Internal,
            Self::ClientIdInvalid => ErrorKind::Validation,
            Self::ClientNotFound => ErrorKind::Validation,
            Self::ClientLookupFailed => ErrorKind::Internal,
            Self::CredentialLookupFailed => ErrorKind::Internal,
            Self::ClientCredentialsInvalid => ErrorKind::Validation,
            Self::ClientAuthRequired => ErrorKind::Validation,
            Self::AssertionIssMissing => ErrorKind::Validation,
            Self::AssertionSubMissing => ErrorKind::Validation,
            Self::AssertionIssSubMismatch => ErrorKind::Validation,
            Self::AssertionAudMismatch => ErrorKind::Validation,
            Self::AssertionExpired => ErrorKind::Validation,
            Self::AssertionNotYetValid => ErrorKind::Validation,
            Self::AssertionHeaderInvalid => ErrorKind::Validation,
            Self::AssertionVerifyFailed => ErrorKind::Validation,
            Self::AssertionAlgUnsupported => ErrorKind::Validation,
            Self::AssertionKeyInvalid => ErrorKind::Validation,
            Self::RefreshTokenVerifyFailed => ErrorKind::Validation,
            Self::SignAccessTokenFailed => ErrorKind::Internal,
            Self::SignIdTokenFailed => ErrorKind::Internal,
            Self::SignRefreshTokenFailed => ErrorKind::Internal,
            Self::SerializeRefreshFailed => ErrorKind::Internal,
            Self::StoreRefreshFailed => ErrorKind::Internal,
            Self::PkceMethodUnsupported => ErrorKind::Validation,
            Self::PkceVerifierMismatch => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::UnsupportedGrantType => 24000,
            Self::ClientIdRequired => 24001,
            Self::CodeLookupFailed => 24002,
            Self::AuthCodeNotFound => 24003,
            Self::CodeClientMismatch => 24004,
            Self::AuthCodeInvalid => 24005,
            Self::DeserializeCodeFailed => 24006,
            Self::RedirectUriMismatch => 24007,
            Self::CodeVerifierRequired => 24008,
            Self::StoredUserOidInvalid => 24009,
            Self::UserLookupFailed => 24010,
            Self::AuthCodeUserNotFound => 24011,
            Self::RevokeCodeFailed => 24012,
            Self::RefreshTokenLookupFailed => 24013,
            Self::RefreshTokenNotFound => 24014,
            Self::RefreshTokenInvalid => 24015,
            Self::DeserializeRefreshFailed => 24016,
            Self::RefreshTokenSubMissing => 24017,
            Self::RefreshTokenUseMissing => 24018,
            Self::RefreshTokenUseInvalid => 24019,
            Self::RefreshTokenClientMismatch => 24020,
            Self::RefreshTokenSubInvalid => 24021,
            Self::RefreshTokenUserNotFound => 24022,
            Self::RevokeRefreshFailed => 24023,
            Self::KeyListFailed => 24024,
            Self::NoSigningKeyAvailable => 24025,
            Self::ClientIdInvalid => 24026,
            Self::ClientNotFound => 24027,
            Self::ClientLookupFailed => 24028,
            Self::CredentialLookupFailed => 24029,
            Self::ClientCredentialsInvalid => 24030,
            Self::ClientAuthRequired => 24031,
            Self::AssertionIssMissing => 24032,
            Self::AssertionSubMissing => 24033,
            Self::AssertionIssSubMismatch => 24034,
            Self::AssertionAudMismatch => 24035,
            Self::AssertionExpired => 24036,
            Self::AssertionNotYetValid => 24037,
            Self::AssertionHeaderInvalid => 24038,
            Self::AssertionVerifyFailed => 24039,
            Self::AssertionAlgUnsupported => 24040,
            Self::AssertionKeyInvalid => 24041,
            Self::RefreshTokenVerifyFailed => 24042,
            Self::SignAccessTokenFailed => 24043,
            Self::SignIdTokenFailed => 24044,
            Self::SignRefreshTokenFailed => 24045,
            Self::SerializeRefreshFailed => 24046,
            Self::StoreRefreshFailed => 24047,
            Self::PkceMethodUnsupported => 24048,
            Self::PkceVerifierMismatch => 24049,
        }
    }
}
