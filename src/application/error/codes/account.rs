define_error_codes! {
    /// Range: 15000-15099
    pub enum AccountErrorCode(module = "account") {
        ValidationFailed = 15000 { kind: Validation },
        UsernameRequired = 15001 { kind: Validation },
        UsernameInvalid = 15002 { kind: Validation },
        EmailRequired = 15003 { kind: Validation },
        EmailInvalid = 15004 { kind: Validation },
        UsernameExists = 15005 { kind: Conflict },
        EmailExists = 15006 { kind: Conflict },
        /// Email delivery is not configured, so no verification can be sent.
        EmailVerificationUnavailable = 15007 { kind: Forbidden },
        EmailVerificationResendTooSoon = 15008 { kind: RateLimit, required: [seconds] },
        EmailVerificationLimitReached = 15009 { kind: RateLimit },
        EmailAlreadyVerified = 15010 { kind: Conflict },
        /// The link is unknown, expired, used, or voided by a later change.
        EmailVerificationInvalid = 15011 { kind: Gone },
        EmailVerificationDeliveryFailed = 15012 { kind: Internal },
    }
}
