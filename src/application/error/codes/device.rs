define_error_codes! {
    /// Error codes for the RFC 8628 device authorization endpoint and the shared
    /// verification interaction. Range: 26000-26099
    pub enum DeviceAuthorizationErrorCode(module = "openid_connect.device") {
        // --- device authorization request ---
        /// Client registration does not permit the device code grant.
        GrantNotAllowed = 26001 { kind: Validation },
        /// `scope` parameter could not be parsed.
        ScopeInvalid = 26002 { kind: Validation },
        /// Requested scope is not assigned to the client.
        ScopeNotAssignedToClient = 26003 { kind: Validation },
        /// The user code space is exhausted for this moment.
        UserCodeUnavailable = 26005 { kind: Internal },
        /// Device code or user code generation failed.
        CodeGenerationFailed = 26006 { kind: Internal },
        /// Database write of the device authorization request failed.
        StoreRequestFailed = 26007 { kind: Internal },
        /// The provider issuer is missing or malformed.
        IssuerInvalid = 26009 { kind: Internal },
        /// The recorded login application domain is malformed.
        LoginDomainInvalid = 26023 { kind: Internal },

        // --- verification interaction ---
        /// The submitted user code is unknown, expired, or already decided.
        UserCodeNotFound = 26010 { kind: Validation },
        /// Database read of the device authorization request failed.
        LoadRequestFailed = 26012 { kind: Internal },
        /// Stored device authorization request could not be deserialized.
        DeserializeRequestFailed = 26013 { kind: Internal },
        /// The request is no longer pending, so the decision was discarded.
        RequestAlreadyDecided = 26014 { kind: Conflict },
        /// The stored device authorization relation is missing or malformed.
        InvalidAuthorizationState = 26015 { kind: Internal },
        /// Database write of the user decision failed.
        StoreDecisionFailed = 26016 { kind: Internal },
        /// The user lookup for the approving account failed.
        UserLookupFailed = 26017 { kind: Internal },
        /// Database read of the client registration failed.
        ClientLookupFailed = 26020 { kind: Internal },
        /// The client registration no longer exists.
        ClientNotFound = 26021 { kind: Validation },
        /// The approving user was not found.
        UserNotFound = 26018 { kind: Validation },
        /// The request expired before the user decided.
        RequestExpired = 26019 { kind: Gone },
        /// The browser answering the verification has no active session.
        VerificationLoginRequired = 26022 { kind: Unauthorized },
    }
}
