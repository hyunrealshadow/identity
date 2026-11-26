define_error_codes! {
    /// Error codes for OIDC userinfo and token validation.
    /// Range: 21000-21099
    pub enum OpenIdConnectErrorCode(module = "openid_connect.user_info") {
        InvalidToken = 21000 { kind: Unauthorized },
        InsufficientScope = 21001 { kind: Forbidden },
        UserNotFound = 21002 { kind: NotFound },
        PostLogoutRedirectUriNotRegistered = 21003 { kind: Validation },
        IdTokenHintIssuerInvalid = 21004 { kind: Validation },
        PostLogoutRedirectUriInvalid = 21005 { kind: Validation },
        LogoutClientRequired = 21006 { kind: Validation },
        LogoutClientInvalid = 21007 { kind: Validation },
        LogoutClientLookupFailed = 21008 { kind: Internal },
        LogoutClientNotFound = 21009 { kind: Validation },
        IdTokenHintInvalid = 21010 { kind: Validation },
        IdTokenHintRequired = 21011 { kind: Validation },
        /// The `Authorization` header does not use the Bearer scheme (RFC 6750).
        BearerSchemeInvalid = 21012 { kind: Validation },
        /// The `Authorization` header is missing (RFC 6750).
        AuthorizationHeaderRequired = 21013 { kind: Validation },
        /// No Bearer token in the `Authorization` header or `access_token` body parameter.
        AccessTokenRequired = 21014 { kind: Validation },
    }
}
