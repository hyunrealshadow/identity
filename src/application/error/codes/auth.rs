define_error_codes! {
    /// Range: 11000-11099
    pub enum AuthErrorCode(module = "auth") {
        UserNotFound = 11000 { kind: NotFound },
        InvalidCredential = 11001 { kind: Unauthorized },
        UserLocked = 11002 { kind: Forbidden },
        UserDisabled = 11003 { kind: Forbidden },
        LoginExpired = 11004 { kind: Gone },
        InvalidLoginState = 11005 { kind: Conflict },
        CredentialTypeUnsupported = 11006 { kind: Validation, required: [credential_type] },
        InvalidOtp = 11007 { kind: Unauthorized },
        TooManyAttempts = 11008 { kind: RateLimit },
        SessionNotFound = 11009 { kind: NotFound, required: [session_id] },
        SessionExpired = 11010 { kind: Unauthorized },
        SessionRevoked = 11011 { kind: Unauthorized },
        IdentifierRequired = 11012 { kind: Validation },
        PasswordTooShort = 11013 { kind: Validation },
        PasswordUnchanged = 11014 { kind: Validation },
        TotpAlreadyEnabled = 11015 { kind: Conflict },
        TotpNotEnabled = 11016 { kind: Conflict },
        InvalidTotpEnrollment = 11017 { kind: Validation },
        /// Withdrawing device authorizations during an account level action failed.
        DeviceAuthorizationRevocationFailed = 11018 { kind: Internal },
        PasskeyLimitReached = 11019 { kind: Conflict, required: [limit] },
        InvalidMfaEnrollment = 11020 { kind: Validation },
        MfaNotEnabled = 11021 { kind: Conflict },
        PasswordTooLong = 11022 { kind: Validation },
        PasswordTooWeak = 11023 { kind: Validation },
        PasswordTooSimilar = 11024 { kind: Validation },
        PasswordBreached = 11025 { kind: Validation },
        PasswordCheckUnavailable = 11026 { kind: Internal },
        /// A failed password while the interaction conceals whether the account
        /// exists: it does not say which of the two was wrong.
        InvalidAccountOrPassword = 11027 { kind: Unauthorized },
        /// Another sign-in email was requested before the resend interval passed.
        EmailCodeResendTooSoon = 11028 { kind: RateLimit, required: [seconds] },
        /// The sign-in email could not be sent.
        EmailDeliveryFailed = 11029 { kind: Internal },
        /// The account cannot replace its password by email: password reset is
        /// off, email cannot be sent, or the account has no password or no
        /// verified email address.
        PasswordResetUnavailable = 11030 { kind: Validation },
        /// The password reset link is wrong, used, or expired.
        PasswordResetLinkInvalid = 11031 { kind: Validation },
        /// Another password reset email was requested before the resend interval
        /// passed.
        PasswordResetResendTooSoon = 11032 { kind: RateLimit, required: [seconds] },
        /// The password reset email could not be sent.
        PasswordResetDeliveryFailed = 11033 { kind: Internal },
        /// The new password repeats one of the account's recent passwords.
        PasswordReused = 11034 { kind: Validation, required: [count] },
        /// Self-registration is off or email cannot be sent.
        RegistrationUnavailable = 11035 { kind: Validation },
        /// The registration link is wrong, used, or expired.
        RegistrationLinkInvalid = 11036 { kind: Validation },
        /// Another registration email was requested before the resend interval
        /// passed.
        RegistrationResendTooSoon = 11037 { kind: RateLimit, required: [seconds] },
        /// The invitation link is wrong, used, expired, or no longer matches the
        /// account.
        InvitationLinkInvalid = 11038 { kind: Validation },
    }
}
