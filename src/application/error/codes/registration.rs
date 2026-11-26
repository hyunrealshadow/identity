define_error_codes! {
    /// Range: 25000-25099
    pub enum RegistrationErrorCode {
        DynamicRegistrationDisabled = 25000 { kind: Validation },
        RedirectUrisRequired = 25001 { kind: Validation },
        UnsupportedApplicationType = 25002 { kind: Validation, required: [application_type] },
        UnsupportedSubjectType = 25003 { kind: Validation, required: [subject_type] },
        ClientCreateFailed = 25004 { kind: Internal },
        InvalidRegistrationAccessToken = 25005 { kind: Unauthorized },
        ClientLookupFailed = 25006 { kind: Internal },
        NoneNotSupported = 25007 { kind: Validation, required: [field] },
        InvalidRedirectUri = 25008 { kind: Validation },
        InvalidClientMetadata = 25009 { kind: Validation },
        ClientDeleteFailed = 25010 { kind: Internal },
        BuiltInClientCannotBeDeleted = 25011 { kind: Validation },
        ClientUpdateFailed = 25012 { kind: Internal },
        ClientUpdateForbidden = 25013 { kind: Forbidden },
    }
}
