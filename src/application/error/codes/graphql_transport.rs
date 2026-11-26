define_error_codes! {
    /// Stable HTTP/GraphQL envelope errors. Range: 28100-28199.
    pub enum GraphqlTransportErrorCode(module = "graphql.transport") {
        InvalidRequest = 28100 { kind: Validation },
        UnsupportedMediaType = 28101 { kind: Validation },
        PayloadTooLarge = 28102 { kind: Validation },
        UriTooLong = 28103 { kind: Validation },
        MethodNotAllowed = 28104 { kind: Validation },
        OriginDenied = 28105 { kind: Forbidden },
        TimedOut = 28106 { kind: Internal },
        Unauthenticated = 28107 { kind: Unauthorized },
        Internal = 28108 { kind: Internal },
        InvalidToken = 28109 { kind: Unauthorized },
        /// The document exceeds the configured selection depth.
        QueryTooDeep = 28110 { kind: Validation, required: [max] },
        /// The document exceeds the configured operation complexity.
        QueryTooComplex = 28111 { kind: Validation, required: [max] },
    }
}
