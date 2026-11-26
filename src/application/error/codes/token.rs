define_error_codes! {
    /// Error codes for `TokenService` and the `/oauth2/token` HTTP endpoint.
    /// Range: 24000-24099
    pub enum TokenErrorCode(module = "openid_connect.token") {
        // --- grant routing ---
        /// `grant_type` is not supported by this endpoint.
        UnsupportedGrantType = 24000 { kind: Validation, required: [grant_type] },
        /// `client_id` parameter is missing from the request.
        ClientIdRequired = 24001 { kind: Validation },

        // --- authorization code exchange ---
        /// Database lookup for the authorization code record failed.
        CodeLookupFailed = 24002 { kind: Internal },
        /// Authorization code was not found.
        AuthCodeNotFound = 24003 { kind: Validation },
        /// Authorization code does not belong to the authenticated client.
        CodeClientMismatch = 24004 { kind: Validation },
        /// Authorization code is revoked or expired.
        AuthCodeInvalid = 24005 { kind: Validation },
        /// Authorization code was already consumed or revoked.
        AuthCodeRevoked = 24052 { kind: Validation },
        /// Authorization code has expired.
        AuthCodeExpired = 24053 { kind: Validation },
        /// Authorization code session was not found.
        AuthCodeSessionNotFound = 24054 { kind: Validation },
        /// Authorization code session is not active.
        AuthCodeSessionInactive = 24055 { kind: Validation },
        /// Authorization code session was revoked.
        AuthCodeSessionRevoked = 24056 { kind: Validation },
        /// Authorization code session has expired.
        AuthCodeSessionExpired = 24057 { kind: Validation },
        /// Authorization code session user does not match.
        AuthCodeSessionUserMismatch = 24058 { kind: Validation },
        /// Authorization code could not be consumed because it is no longer active.
        AuthCodeClaimFailed = 24059 { kind: Validation },
        /// Failed to look up the authorization code session.
        AuthCodeSessionLookupFailed = 24060 { kind: Internal },

        /// Failed to deserialize stored `AuthorizationCodeData`.
        DeserializeCodeFailed = 24006 { kind: Internal },
        /// `redirect_uri` does not match the one stored in the authorization code.
        RedirectUriMismatch = 24007 { kind: Validation },
        /// `code_verifier` is required but missing.
        CodeVerifierRequired = 24008 { kind: Validation },
        /// Stored `user_oid` in the authorization code is not a valid UUID.
        StoredUserOidInvalid = 24009 { kind: Internal },
        /// Database lookup for the user referenced by the authorization code failed.
        UserLookupFailed = 24010 { kind: Internal },
        /// User referenced by the authorization code was not found.
        AuthCodeUserNotFound = 24011 { kind: Validation },
        /// Database revocation of the used authorization code failed.
        RevokeCodeFailed = 24012 { kind: Internal },

        // --- refresh token exchange ---
        /// Database lookup for the refresh token record failed.
        RefreshTokenLookupFailed = 24013 { kind: Internal },
        /// Refresh token was not found.
        RefreshTokenNotFound = 24014 { kind: Validation },
        /// Refresh token is revoked or expired.
        RefreshTokenInvalid = 24015 { kind: Validation },
        /// Failed to deserialize stored `RefreshTokenData`.
        DeserializeRefreshFailed = 24016 { kind: Internal },
        /// Refresh token JWT is missing the `sub` claim.
        RefreshTokenSubMissing = 24017 { kind: Validation },
        /// Refresh token JWT is missing the `token_use` claim.
        RefreshTokenUseMissing = 24018 { kind: Validation },
        /// Refresh token `token_use` claim is not `"refresh_token"`.
        RefreshTokenUseInvalid = 24019 { kind: Validation },
        /// Refresh token does not belong to the authenticated client.
        RefreshTokenClientMismatch = 24020 { kind: Validation },
        /// Refresh token `sub` claim is not a valid UUID.
        RefreshTokenSubInvalid = 24021 { kind: Validation },
        /// User referenced by the refresh token was not found.
        RefreshTokenUserNotFound = 24022 { kind: Validation },
        /// Database revocation of the old refresh token failed.
        RevokeRefreshFailed = 24023 { kind: Internal },

        // --- signing key ---
        /// Database call to list available asymmetric signing keys failed.
        KeyListFailed = 24024 { kind: Internal },
        /// No RS256-capable signing key is available.
        NoSigningKeyAvailable = 24025 { kind: Internal },

        // --- client authentication ---
        /// `client_id` is not a valid UUID.
        ClientIdInvalid = 24026 { kind: Validation },
        /// Client was not found.
        ClientNotFound = 24027 { kind: Validation },
        /// Database call to find client failed.
        ClientLookupFailed = 24028 { kind: Internal },
        /// Database call to find client credentials failed.
        CredentialLookupFailed = 24029 { kind: Internal },
        /// Client secret does not match any stored credential.
        ClientCredentialsInvalid = 24030 { kind: Validation },
        /// No client authentication was provided.
        ClientAuthRequired = 24031 { kind: Validation },

        // --- private key JWT client assertion ---
        /// Client assertion JWT is missing the `iss` claim.
        AssertionIssMissing = 24032 { kind: Validation },
        /// Client assertion JWT is missing the `sub` claim.
        AssertionSubMissing = 24033 { kind: Validation },
        /// Assertion `iss`/`sub` do not equal `client_id`.
        AssertionIssSubMismatch = 24034 { kind: Validation },
        /// Assertion `aud` does not include the issuer URL.
        AssertionAudMismatch = 24035 { kind: Validation },
        /// Client assertion JWT has expired.
        AssertionExpired = 24036 { kind: Validation },
        /// Client assertion JWT `nbf` is in the future.
        AssertionNotYetValid = 24037 { kind: Validation },
        /// Failed to decode the client assertion JWT header.
        AssertionHeaderInvalid = 24038 { kind: Validation },
        /// Failed to verify the client assertion signature.
        AssertionVerifyFailed = 24039 { kind: Validation },
        /// Client assertion signing algorithm is not supported.
        AssertionAlgUnsupported = 24040 { kind: Validation, required: [alg] },
        /// PEM public key for the client assertion is invalid.
        AssertionKeyInvalid = 24041 { kind: Validation },

        // --- refresh token verification ---
        /// No key could verify the refresh token JWT.
        RefreshTokenVerifyFailed = 24042 { kind: Validation },

        // --- token signing ---
        /// Failed to build or sign the access token JWT.
        SignAccessTokenFailed = 24043 { kind: Internal },
        /// Failed to build or sign the ID token JWT.
        SignIdTokenFailed = 24044 { kind: Internal },
        /// Failed to build or sign the refresh token JWT.
        SignRefreshTokenFailed = 24045 { kind: Internal },

        // --- refresh token storage ---
        /// Failed to serialize `RefreshTokenData`.
        SerializeRefreshFailed = 24046 { kind: Internal },
        /// Database write of the refresh token record failed.
        StoreRefreshFailed = 24047 { kind: Internal },

        // --- PKCE ---
        /// `code_challenge_method` is not `S256`.
        PkceMethodUnsupported = 24048 { kind: Validation, required: [code_challenge_method] },
        /// `code_verifier` does not match the stored `code_challenge`.
        PkceVerifierMismatch = 24049 { kind: Validation },

        // --- id token encryption ---
        /// Client has no encryption key configured.
        EncryptionKeyNotFound = 24050 { kind: Internal },
        /// JWE encryption of the token failed.
        EncryptionFailed = 24051 { kind: Internal },
        /// Client registration does not permit the requested grant type.
        ClientGrantNotAllowed = 24061 { kind: Validation },
        /// No device authorization request matches the presented device code.
        DeviceCodeNotFound = 24062 { kind: Validation },
        /// The device request belongs to another client.
        DeviceCodeClientMismatch = 24063 { kind: Validation },
        /// The user has not decided yet; the client should keep polling.
        DeviceCodePending = 24064 { kind: Validation },
        /// The client polls faster than the advertised interval.
        DeviceCodeSlowDown = 24065 { kind: Validation },
        /// The user denied the device authorization request.
        DeviceCodeDenied = 24066 { kind: Validation },
        /// The device authorization request expired.
        DeviceCodeExpired = 24067 { kind: Validation },
        /// The device authorization relation was revoked.
        DeviceCodeRevoked = 24068 { kind: Validation },
        /// The approving user no longer exists or cannot receive tokens.
        DeviceCodeUserNotFound = 24069 { kind: Validation },
        /// Stored device authorization request is inconsistent.
        DeviceRequestStateInvalid = 24070 { kind: Internal },
        /// Database read of the device authorization request failed.
        DeviceRequestLookupFailed = 24071 { kind: Internal },
        /// Database read of the device authorization relation failed.
        DeviceRelationLookupFailed = 24072 { kind: Internal },
        /// Committing the device code consumption and token records failed.
        DeviceRedemptionFailed = 24073 { kind: Internal },
        /// A refresh asked for scope the original authorization did not grant.
        RefreshScopeNotAllowed = 24074 { kind: Validation },
        /// Client credentials requested an unassigned or user-bound scope.
        ClientCredentialsScopeNotAllowed = 24075 { kind: Validation },
    }
}
