define_error_codes! {
    /// Range: 20000-20099
    pub enum ProviderErrorCode(module = "openid_connect.provider") {
        NotInitialized = 20000 { kind: Validation },
        DomainMissing = 20001 { kind: Validation },
        IssuerMustUseHttps = 20002 { kind: Validation },
        IssuerMustNotHaveQueryOrFragment = 20003 { kind: Validation },
        IssuerUrlParseFailed = 20004 { kind: Internal },
        KeyLookupFailed = 20005 { kind: Internal },
    }
}
