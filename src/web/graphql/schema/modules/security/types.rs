use async_graphql::{Enum, InputObject, Object};
use identity_application::user::OtpAlgorithm;

#[derive(async_graphql::SimpleObject)]
pub(super) struct RecoveryCodeEnrollmentPayload {
    pub recovery_codes: Vec<String>,
    pub enrollment_token: Option<String>,
}

pub(super) struct AccountSecurity {
    totp_enabled: bool,
    passkey_enabled: bool,
    recovery_codes_remaining: i32,
    preferred_mfa_method: identity_domain::user::MfaMethod,
}

impl AccountSecurity {
    pub(super) fn new(
        totp_enabled: bool,
        passkey_enabled: bool,
        recovery_codes_remaining: i32,
        preferred_mfa_method: identity_domain::user::MfaMethod,
    ) -> Self {
        Self {
            totp_enabled,
            passkey_enabled,
            recovery_codes_remaining,
            preferred_mfa_method,
        }
    }
}

#[Object]
impl AccountSecurity {
    async fn mfa_enabled(&self) -> bool {
        self.totp_enabled || self.passkey_enabled
    }

    async fn preferred_mfa_method(&self) -> &'static str {
        self.preferred_mfa_method.as_str()
    }

    async fn totp_enabled(&self) -> bool {
        self.totp_enabled
    }

    async fn recovery_codes_remaining(&self) -> i32 {
        self.recovery_codes_remaining
    }
}

#[derive(InputObject)]
pub(super) struct ChangePasswordInput {
    pub new_password: String,
    pub client_mutation_id: Option<String>,
}

pub(super) struct ChangePasswordPayload {
    changed: bool,
    revoked_other_sessions: u32,
    session_revocation_failures: u32,
    client_mutation_id: Option<String>,
}

impl ChangePasswordPayload {
    pub(super) fn new(
        revoked_other_sessions: u32,
        session_revocation_failures: u32,
        client_mutation_id: Option<String>,
    ) -> Self {
        Self {
            changed: true,
            revoked_other_sessions,
            session_revocation_failures,
            client_mutation_id,
        }
    }
}

#[Object]
impl ChangePasswordPayload {
    async fn changed(&self) -> bool {
        self.changed
    }

    /// Number of other sessions that were revoked after the password change.
    async fn revoked_other_sessions(&self) -> u32 {
        self.revoked_other_sessions
    }

    /// Sessions that could not be revoked. A non-zero value means the password
    /// change succeeded but the revocation batch partially failed.
    async fn session_revocation_failures(&self) -> u32 {
        self.session_revocation_failures
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(super) struct BeginTotpEnrollmentPayload {
    secret: String,
    otp_auth_uri: String,
    enrollment_token: String,
    recovery_codes: Vec<String>,
    client_mutation_id: Option<String>,
}

impl BeginTotpEnrollmentPayload {
    pub(super) fn new(
        secret: String,
        otp_auth_uri: String,
        enrollment_token: String,
        recovery_codes: Vec<String>,
        client_mutation_id: Option<String>,
    ) -> Self {
        Self {
            secret,
            otp_auth_uri,
            enrollment_token,
            recovery_codes,
            client_mutation_id,
        }
    }
}

#[Object]
impl BeginTotpEnrollmentPayload {
    async fn secret(&self) -> &str {
        &self.secret
    }

    async fn otp_auth_uri(&self) -> &str {
        &self.otp_auth_uri
    }

    async fn enrollment_token(&self) -> &str {
        &self.enrollment_token
    }

    async fn recovery_codes(&self) -> &[String] {
        &self.recovery_codes
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[derive(InputObject)]
pub(super) struct ConfirmTotpEnrollmentInput {
    pub enrollment_token: String,
    pub code: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "TotpAlgorithm")]
pub(super) enum TotpAlgorithmInput {
    #[graphql(name = "SHA1")]
    Sha1,
    #[graphql(name = "SHA256")]
    Sha256,
    #[graphql(name = "SHA512")]
    Sha512,
}

impl From<TotpAlgorithmInput> for OtpAlgorithm {
    fn from(value: TotpAlgorithmInput) -> Self {
        match value {
            TotpAlgorithmInput::Sha1 => Self::Sha1,
            TotpAlgorithmInput::Sha256 => Self::Sha256,
            TotpAlgorithmInput::Sha512 => Self::Sha512,
        }
    }
}

#[derive(InputObject)]
pub(super) struct ChangeTotpEnrollmentAlgorithmInput {
    pub enrollment_token: String,
    pub algorithm: TotpAlgorithmInput,
    pub client_mutation_id: Option<String>,
}

pub(super) struct RecoveryCodesPayload {
    recovery_codes: Vec<String>,
    client_mutation_id: Option<String>,
}

impl RecoveryCodesPayload {
    pub(super) fn new(recovery_codes: Vec<String>, client_mutation_id: Option<String>) -> Self {
        Self {
            recovery_codes,
            client_mutation_id,
        }
    }
}

#[Object]
impl RecoveryCodesPayload {
    async fn recovery_codes(&self) -> &[String] {
        &self.recovery_codes
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(super) struct TotpChangedPayload {
    changed: bool,
    client_mutation_id: Option<String>,
}

impl TotpChangedPayload {
    pub(super) fn new(client_mutation_id: Option<String>) -> Self {
        Self {
            changed: true,
            client_mutation_id,
        }
    }
}

#[Object]
impl TotpChangedPayload {
    async fn changed(&self) -> bool {
        self.changed
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}
