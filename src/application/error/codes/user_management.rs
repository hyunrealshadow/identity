//! User management error catalog. Reserved range: 16000-16099.
//!
//! These codes describe P2 instance-user management operations only. They are
//! deliberately separate from account self-service (15000), authentication
//! (11000) and management authorization (27000). Semantically identical
//! username and email failures reuse the account inventory (15001-15006); the
//! six former 16001-16006 slots remain reserved and are not reissued.
//! Semantically identical authorization failures reuse the 27000 inventory.

define_error_codes! {
    pub enum UserManagementErrorCode(module = "user.management") {
        ValidationFailed = 16000 { kind: Validation, optional: [field] },
        UserNotFound = 16007 { kind: NotFound },
        VersionConflict = 16008 { kind: Conflict, required: [current_version] },
        InvalidVersion = 16009 { kind: Validation },
        ReasonTooLong = 16011 { kind: Validation, required: [max] },
        PageSizeInvalid = 16012 { kind: Validation, required: [max] },
        PageArgumentsConflict = 16013 { kind: Validation },
        InvalidFilter = 16014 { kind: Validation, required: [field], optional: [max] },
        InvalidDateRange = 16015 { kind: Validation, required: [field] },
        InvalidCursor = 16016 { kind: Validation },
        InvalidTheme = 16017 { kind: Validation },
        InvalidClientMutationId = 16018 { kind: Validation, required: [max] },
        StorageFailed = 16019 { kind: Internal },
        AccessInvalidationFailed = 16020 { kind: Internal },
        /// Only a disabled user may be deleted.
        UserNotDisabled = 16021 { kind: Conflict },
        /// Second factors are cleared only from an account that still has a
        /// password to sign in with.
        UserHasNoPassword = 16022 { kind: Conflict },
        /// The session does not belong to the user.
        SessionNotFound = 16023 { kind: NotFound },
        /// Operators manage their own sign-in methods in the account center.
        SelfCredentialActionNotAllowed = 16024 { kind: Conflict },
        /// An invitation needs email delivery to be configured.
        InvitationUnavailable = 16025 { kind: Forbidden },
        /// The user has no outstanding invitation, or has already accepted it.
        InvitationNotPending = 16026 { kind: Conflict },
        /// Another invitation email was sent before the resend interval passed.
        InvitationResendTooSoon = 16027 { kind: RateLimit, required: [seconds] },
        /// The invitation email could not be sent.
        InvitationDeliveryFailed = 16028 { kind: Internal },
        /// A new user needs either an initial password or an invitation.
        CredentialChoiceRequired = 16029 { kind: Validation },
        /// Disabled users must be enabled before sending an invitation.
        InvitationUserDisabled = 16030 { kind: Conflict },
    }
}
