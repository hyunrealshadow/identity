use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for `TokenService` and the `/oauth2/token` HTTP endpoint.
/// Range: 7000–7099
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
            Self::UnsupportedGrantType => 7000,
            Self::ClientIdRequired => 7001,
            Self::CodeLookupFailed => 7002,
            Self::AuthCodeNotFound => 7003,
            Self::CodeClientMismatch => 7004,
            Self::AuthCodeInvalid => 7005,
            Self::DeserializeCodeFailed => 7006,
            Self::RedirectUriMismatch => 7007,
            Self::CodeVerifierRequired => 7008,
            Self::StoredUserOidInvalid => 7009,
            Self::UserLookupFailed => 7010,
            Self::AuthCodeUserNotFound => 7011,
            Self::RevokeCodeFailed => 7012,
            Self::RefreshTokenLookupFailed => 7013,
            Self::RefreshTokenNotFound => 7014,
            Self::RefreshTokenInvalid => 7015,
            Self::DeserializeRefreshFailed => 7016,
            Self::RefreshTokenSubMissing => 7017,
            Self::RefreshTokenUseMissing => 7018,
            Self::RefreshTokenUseInvalid => 7019,
            Self::RefreshTokenClientMismatch => 7020,
            Self::RefreshTokenSubInvalid => 7021,
            Self::RefreshTokenUserNotFound => 7022,
            Self::RevokeRefreshFailed => 7023,
            Self::KeyListFailed => 7024,
            Self::NoSigningKeyAvailable => 7025,
            Self::ClientIdInvalid => 7026,
            Self::ClientNotFound => 7027,
            Self::ClientLookupFailed => 7028,
            Self::CredentialLookupFailed => 7029,
            Self::ClientCredentialsInvalid => 7030,
            Self::ClientAuthRequired => 7031,
            Self::AssertionIssMissing => 7032,
            Self::AssertionSubMissing => 7033,
            Self::AssertionIssSubMismatch => 7034,
            Self::AssertionAudMismatch => 7035,
            Self::AssertionExpired => 7036,
            Self::AssertionNotYetValid => 7037,
            Self::AssertionHeaderInvalid => 7038,
            Self::AssertionVerifyFailed => 7039,
            Self::AssertionAlgUnsupported => 7040,
            Self::AssertionKeyInvalid => 7041,
            Self::RefreshTokenVerifyFailed => 7042,
            Self::SignAccessTokenFailed => 7043,
            Self::SignIdTokenFailed => 7044,
            Self::SignRefreshTokenFailed => 7045,
            Self::SerializeRefreshFailed => 7046,
            Self::StoreRefreshFailed => 7047,
            Self::PkceMethodUnsupported => 7048,
            Self::PkceVerifierMismatch => 7049,
        }
    }
}
