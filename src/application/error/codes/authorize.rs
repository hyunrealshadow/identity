define_error_codes! {
    /// Error codes for `AuthorizeService` (OIDC authorization request processing).
    /// Range: 23000-23099
    pub enum AuthorizeErrorCode(module = "openid_connect.authorize") {
        // --- client lookup ---
        /// `client_id` is not a valid UUID.
        ClientIdInvalid = 23000 { kind: Validation },
        /// OpenID Connect client not found.
        ClientNotFound = 23001 { kind: Validation },
        /// Database call to find client failed.
        ClientLookupFailed = 23002 { kind: Internal },

        // --- basic parameter validation ---
        /// `response_type` value could not be parsed.
        ResponseTypeInvalid = 23003 { kind: Validation, required: [response_type] },
        /// `response_mode` value could not be parsed.
        ResponseModeInvalid = 23066 { kind: Validation, required: [response_mode] },
        /// `redirect_uri` is not a valid URL.
        RedirectUriInvalid = 23004 { kind: Validation },
        /// `scope` value could not be parsed.
        ScopeInvalid = 23005 { kind: Validation },
        /// The response type returns an ID token, but `openid` was not requested.
        OpenidScopeRequired = 23006 { kind: Validation },
        /// `display` parameter value could not be parsed.
        DisplayValueInvalid = 23007 { kind: Validation, required: [display] },
        /// `prompt` parameter value could not be parsed.
        PromptValueInvalid = 23008 { kind: Validation, required: [prompt] },
        /// `prompt` contains `none` along with other values.
        PromptNoneCombined = 23057 { kind: Validation },
        /// `max_age` parameter is not a valid integer.
        MaxAgeInvalid = 23009 { kind: Validation },
        /// `request_uri` parameter is not a valid URL.
        RequestUriInvalid = 23010 { kind: Validation },
        /// `code_challenge_method` value could not be parsed.
        CodeChallengeMethodInvalid = 23011 { kind: Validation, required: [code_challenge_method] },
        /// Both `request` and `request_uri` were provided simultaneously.
        RequestAndUriConflict = 23012 { kind: Validation },
        /// One or more required parameters are missing or blank.
        RequiredParamMissing = 23013 { kind: Validation, required: [fields] },

        // --- redirect URI ---
        /// `redirect_uri` is not registered for the client.
        RedirectUriNotRegistered = 23014 { kind: Validation },

        // --- request_uri validation ---
        /// `request_uri` scheme is not `https`.
        RequestUriNotHttps = 23015 { kind: Validation },
        /// `request_uri` contains a fragment component.
        RequestUriHasFragment = 23016 { kind: Validation },
        /// `request_uri` targets a loopback or private-network host.
        RequestUriUnsafeHost = 23017 { kind: Validation },
        /// `request_uri` is not registered for the client.
        RequestUriNotRegistered = 23018 { kind: Validation },

        // --- request_uri fetching ---
        /// HTTP GET of `request_uri` failed.
        RequestUriFetchFailed = 23019 { kind: Validation },
        /// `request_uri` response returned a non-200 status.
        RequestUriNot200 = 23020 { kind: Validation },
        /// `request_uri` response exceeded the maximum allowed size.
        RequestUriTooLarge = 23021 { kind: Validation },
        /// Failed to read or UTF-8 decode the `request_uri` response body.
        RequestUriReadFailed = 23022 { kind: Validation },

        // --- request object parsing ---
        /// Failed to decode the JWT header of the request object.
        RequestObjectHeaderInvalid = 23023 { kind: Validation },
        /// Failed to decode an unsigned (`alg=none`) request object.
        RequestObjectDecodeFailed = 23024 { kind: Validation },
        /// Request object signing algorithm is not supported.
        RequestObjectAlgUnsupported = 23025 { kind: Validation, required: [alg] },

        // --- request object verification ---
        /// Database call to find client credential failed.
        CredentialLookupFailed = 23026 { kind: Internal },
        /// PEM public key stored for the client is invalid.
        RequestObjectKeyInvalid = 23027 { kind: Validation },
        /// Signature verification of the request object failed.
        RequestObjectVerifyFailed = 23028 { kind: Validation },

        // --- request object claims ---
        /// Request object `iss` claim does not match `client_id`.
        RequestObjectIssMismatch = 23029 { kind: Validation },
        /// Request object `aud` claim does not include the issuer.
        RequestObjectAudMismatch = 23030 { kind: Validation },
        /// Request object `exp` claim is in the past.
        RequestObjectExpired = 23031 { kind: Validation },
        /// Request object `nbf` claim is in the future.
        RequestObjectNotYetValid = 23032 { kind: Validation },
        /// Request object `iat` claim is in the future.
        RequestObjectIatFuture = 23033 { kind: Validation },
        /// A field in the request object does not match the corresponding outer parameter.
        RequestObjectFieldMismatch = 23034 { kind: Validation, optional: [field] },
        /// A JSON field in the request object could not be parsed.
        RequestObjectJsonInvalid = 23035 { kind: Validation },

        // --- claims parameter ---
        /// `claims` parameter is not valid JSON.
        ClaimsParamInvalid = 23036 { kind: Validation },
        /// `claims` parameter is not a JSON object.
        ClaimsNotObject = 23037 { kind: Validation },
        /// `claims.id_token` or `claims.userinfo` is not a JSON object.
        ClaimsFieldNotObject = 23038 { kind: Validation },

        // --- request object payload decoding (unverified) ---
        /// Request object does not have a valid JWT segment structure.
        RequestObjectEncodingInvalid = 23039 { kind: Validation },
        /// Request object payload segment is not valid base64.
        RequestObjectBase64Invalid = 23040 { kind: Validation },
        /// Request object payload is not valid JSON.
        RequestObjectPayloadInvalid = 23041 { kind: Validation },

        // --- persistence ---
        /// Failed to serialize `AuthorizationRequestData`.
        SerializeRequestFailed = 23042 { kind: Internal },
        /// Database write of authorization request failed.
        StoreRequestFailed = 23043 { kind: Internal },
        /// Database write of pending login flow failed.
        StoreLoginFailed = 23044 { kind: Internal },

        // --- loading stored state ---
        /// Database read of client authorization record failed.
        LoadRequestFailed = 23045 { kind: Internal },
        /// Authorization request record was not found.
        AuthzRequestNotFound = 23046 { kind: Validation },
        /// Stored record type is not `AuthorizationRequest`.
        AuthzRequestTypeMismatch = 23047 { kind: Validation },
        /// Failed to deserialize stored `AuthorizationRequestData`.
        DeserializeRequestFailed = 23048 { kind: Internal },
        /// Stored `client_id` is not a valid UUID (data integrity error).
        StoredClientIdInvalid = 23049 { kind: Internal },
        /// Database read of login flow record failed.
        LoadLoginFailed = 23050 { kind: Internal },
        /// Login flow record was not found.
        LoginNotFound = 23051 { kind: Validation },
        /// Stored `redirect_uri` is not a valid URL (data integrity error).
        StoredRedirectUriInvalid = 23052 { kind: Internal },

        // --- code issuance ---
        /// Failed to serialize `AuthorizationCodeData`.
        SerializeCodeFailed = 23053 { kind: Internal },
        /// Database write of authorization code failed.
        StoreCodeFailed = 23054 { kind: Internal },

        // --- login_id ---
        /// Encrypted login_id decryption or parsing failed.
        LoginIdInvalid = 23055 { kind: Validation },
        /// Requested scope is not assigned to the client.
        ScopeNotAssignedToClient = 23056 { kind: Validation, required: [scopes] },
        /// Nonce is required for implicit flow.
        ImplicitNonceRequired = 23058 { kind: Validation },
        /// User lookup failed during token issuance.
        ImplicitUserNotFound = 23059 { kind: Validation },
        /// `id_token_hint` issuer is missing, malformed, or not this provider.
        IdTokenHintIssuerInvalid = 23060 { kind: Validation },
        /// Encrypted request objects (JWE / Nested JWT) are not supported.
        RequestObjectEncryptionUnsupported = 23061 { kind: Validation },
        /// Authorization request interaction state was already updated or completed.
        AuthzInteractionConflict = 23062 { kind: Validation },
        /// Stored data-protected session ID could not be decrypted or parsed.
        StoredSessionIdInvalid = 23063 { kind: Internal },
        /// Client has no encryption key configured.
        EncryptionKeyNotFound = 23064 { kind: Internal },
        /// JWE encryption of the token failed.
        EncryptionFailed = 23065 { kind: Internal },
        /// Client does not have an `initiate_login_uri`.
        InitiateLoginUriNotRegistered = 23067 { kind: Validation },
        /// Client registration does not permit a grant required by the request.
        ClientGrantNotAllowed = 23068 { kind: Validation },
    }
}
