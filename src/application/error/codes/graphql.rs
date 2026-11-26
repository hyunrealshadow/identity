define_error_codes! {
    /// Stable GraphQL execution and schema errors. Range: 28000-28099.
    ///
    /// These codes describe failures that happen before or around a resolver
    /// result: guards, input validators, Global ID / cursor decoding, pagination
    /// checks and internal adapter failures. They are deliberately separate from
    /// the transport envelope codes (`GraphqlTransportErrorCode`, 28100-28199).
    pub enum GraphqlErrorCode(module = "graphql") {
        ValidationFailed = 28000 { kind: Validation },
        InvalidCursor = 28001 { kind: Validation },
        PageSizeInvalid = 28002 { kind: Validation, required: [max] },
        InvalidGlobalId = 28003 { kind: Validation },
        UnsupportedNodeType = 28004 { kind: Validation },
        InsufficientScope = 28005 { kind: Forbidden, required: [scope] },
        UserAuthenticationRequired = 28006 { kind: Unauthorized },
        Forbidden = 28007 { kind: Forbidden },
        RecentAuthenticationRequired = 28008 { kind: Forbidden },
        BrowserSessionRequired = 28009 { kind: Forbidden },
        InvalidTheme = 28010 { kind: Validation },
        Internal = 28011 { kind: Internal },
        AuthenticationContextUnavailable = 28012 { kind: Unauthorized },
        InvalidSessionId = 28013 { kind: Validation },
        PageArgumentsConflict = 28014 { kind: Validation },
        InstanceMetadataUnavailable = 28015 { kind: Internal },
        InvalidPasskeyChallenge = 28016 { kind: Validation },
        InvalidPasskeyId = 28017 { kind: Validation },
        SerializationFailed = 28018 { kind: Internal },
        AccountUnavailable = 28019 { kind: NotFound },
    }
}
