//! Audit log query error catalog. Reserved range: 30000-30099.

define_error_codes! {
    pub enum AuditErrorCode(module = "audit") {
        InvalidCursor = 30000 { kind: Validation },
        InvalidPageSize = 30001 { kind: Validation, required: [max] },
        InvalidTimeZone = 30002 { kind: Validation, required: [value] },
        QueryTooLong = 30003 { kind: Validation, required: [max], optional: [actual] },
        QueryTooManyClauses = 30004 { kind: Validation, required: [max] },
        QueryTooDeep = 30005 { kind: Validation, required: [max] },
        QuerySyntaxError = 30006 { kind: Validation },
        QueryUnknownField = 30007 { kind: Validation, required: [field] },
        QueryInvalidDate = 30008 { kind: Validation, required: [value] },
        QueryInvalidIdentifier = 30009 { kind: Validation, required: [field, value] },
        QueryUnsupportedOperator = 30010 { kind: Validation, required: [field] },
        QueryUnsupportedRangeField = 30011 { kind: Validation, required: [field] },
        QueryUnsupportedRegex = 30012 { kind: Validation },
        QueryUnsupportedSyntax = 30013 { kind: Validation },
        QueryUnknownValue = 30014 { kind: Validation, required: [field, value] },
    }
}
