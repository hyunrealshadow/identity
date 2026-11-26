define_error_codes! {
    /// Range: 13000-13099
    pub enum InstallErrorCode {
        AlreadyInitialized = 13000 { kind: Conflict },
        UsernameRequired = 13001 { kind: Validation },
        EmailRequired = 13002 { kind: Validation },
        PasswordRequired = 13003 { kind: Validation },
        DomainRequired = 13004 { kind: Validation },
        DomainInvalid = 13005 { kind: Validation },
        EmailInvalid = 13006 { kind: Validation },
        UsernameExists = 13007 { kind: Conflict },
        EmailExists = 13008 { kind: Conflict },
        UnsupportedAlgorithm = 13009 { kind: Validation, required: [algorithm] },
        ApplicationUrlInvalid = 13010 { kind: Validation },
        ConsoleUrlRequired = 13011 { kind: Validation },
        ConsoleUrlInvalid = 13012 { kind: Validation },
    }
}
