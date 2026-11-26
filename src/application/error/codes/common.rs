define_error_codes! {
    /// Range: 10000-10099
    pub enum CommonErrorCode(module = "common") {
        InvalidRequest = 10000 { kind: Validation },
        InternalError = 10001 { kind: Internal },
        ValidationFailed = 10002 { kind: Validation },
        Unauthorized = 10003 { kind: Unauthorized },
        Forbidden = 10004 { kind: Forbidden },
        NotFound = 10005 { kind: NotFound },
        InvalidTarget = 10006 { kind: Validation },
        ResourceLookupFailed = 10007 { kind: Internal },
        PushedRequestStorageFailed = 10008 { kind: Internal },
        InvalidScope = 10009 { kind: Validation },
        InvalidTimeZone = 10010 { kind: Validation },
    }
}
