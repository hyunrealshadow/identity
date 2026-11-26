define_error_codes! {
    /// Error codes for the `/oauth2/authorize` HTTP layer:
    /// request extraction, method validation, and interaction routing.
    /// Range: 22000-22099
    pub enum AuthorizeHttpErrorCode(module = "openid_connect.authorize_http") {
        /// POST request does not use `application/x-www-form-urlencoded` Content-Type.
        PostContentTypeInvalid = 22000 { kind: Validation },
        /// HTTP method is neither GET nor POST.
        MethodNotAllowed = 22001 { kind: Validation, required: [method] },
        /// One or more required OAuth parameters are missing.
        RequiredParamMissing = 22002 { kind: Validation, required: [fields] },
        /// Internal client reached the authorize endpoint without an active session.
        InternalClientLoginRequired = 22003 { kind: Validation },
        /// Consent request references an account with no matching active session.
        ConsentSessionNotFound = 22004 { kind: Validation },
        /// The domain the login application is served from is not configured.
        LoginDomainNotConfigured = 22006 { kind: Internal, required: [interaction] },
    }
}
