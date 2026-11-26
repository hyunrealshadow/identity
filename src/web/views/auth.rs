//! Authentication API request and response DTOs.
//!
//! All external `id` fields are encrypted login.oid values.

use chrono::{DateTime, Utc};
use identity_application::{
    authentication::passkey::{PasskeyAssertion, PasskeyOptions},
    user::{CredentialType, OtpAlgorithm},
};
use identity_domain::auth::LoginStatus;
use serde::{Deserialize, Serialize};

// ─── Common Error Response ───────────────────────────────────────────────────

/// Unified error response body.
#[derive(Debug, Serialize)]
pub struct BusinessErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    /// Machine-readable numeric error code, e.g. `11001`.
    pub code: u32,
    /// Localized human-readable message.
    pub message: String,
    /// Field-specific validation errors. Omitted for non-validation errors.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldErrorDetail>,
    /// What the caller can do to be allowed; same shape as GraphQL errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct FieldErrorDetail {
    /// Stable request field path, e.g. `email` or `redirect_uris.0`.
    pub field: String,
    /// Machine-readable numeric field error code.
    pub code: u32,
    /// Localized human-readable field error message.
    pub message: String,
}

impl BusinessErrorResponse {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code,
                message: message.into(),
                fields: Vec::new(),
                challenge: None,
            },
        }
    }

    pub fn with_fields(mut self, fields: Vec<FieldErrorDetail>) -> Self {
        self.error.fields = fields;
        self
    }

    pub fn with_challenge(mut self, challenge: Option<serde_json::Value>) -> Self {
        self.error.challenge = challenge;
        self
    }
}

// ─── Account Picker ──────────────────────────────────────────────────────────

/// `GET /api/auth/sessions/active` response.
#[derive(Debug, Serialize)]
pub struct ActiveAccountsResponse {
    pub accounts: Vec<AccountItem>,
    pub csrf_token: String,
    pub sessions: Vec<String>,
}

/// A single logged-in account entry.
#[derive(Debug, Serialize)]
pub struct AccountItem {
    /// Data-protected session.oid, externally named `id`.
    pub id: String,
    /// User display name.
    pub name: String,
    /// Full email (not masked — this is the user's own account list).
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Last active timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<DateTime<Utc>>,
}

// ─── Select Existing Account ─────────────────────────────────────────────────

/// `POST /api/auth/login/select` request.
#[derive(Debug, Deserialize)]
pub struct SelectAccountRequest {
    /// Data-protected session.oid to select.
    pub id: String,
    /// Encrypted login.oid — used to enforce `prompt=login` (reject selection
    /// and force fresh authentication).
    pub login_id: String,
}

/// `POST /api/auth/login/select` response (success).
#[derive(Debug, Serialize)]
pub struct SelectAccountResponse {
    pub status: &'static str,
    pub session: SessionInfo,
    pub sessions: Vec<String>,
    pub continue_uri: String,
}

// ─── Identifier Step ─────────────────────────────────────────────────────────

/// `POST /api/auth/login/identifier` request.
#[derive(Debug, Deserialize)]
pub struct IdentifierRequest {
    /// Encrypted login.oid to advance.
    pub id: String,
    /// Email or username.
    pub identifier: String,
}

/// `POST /api/auth/login/identifier` response (success).
#[derive(Debug, Serialize)]
pub struct IdentifierResponse {
    /// Encrypted login.oid — must be carried to subsequent steps.
    pub id: String,
    /// Current login flow status.
    pub status: LoginStatus,
    /// Credential types available for this user, e.g. `["password"]`.
    pub credential_types: Vec<CredentialType>,
    pub preferred_credential_type: Option<CredentialType>,
    /// User display info. Absent while the interaction conceals whether an
    /// account exists; `identifier` is presented instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDisplayInfo>,
    /// The identifier as entered, while account existence is concealed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginClientDisplay {
    pub name: String,
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginStatusResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<LoginClientDisplay>,
    /// Encrypted login.oid.
    pub id: String,
    pub status: LoginStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDisplayInfo>,
    /// The identifier as entered, presented instead of `user` while the
    /// interaction conceals whether an account exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Credential types available to the bound user. Empty before an account
    /// has been selected.
    pub credential_types: Vec<CredentialType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_credential_type: Option<CredentialType>,
    /// Prompt value from the original authorization request (`"login"`,
    /// `"consent"`, `"select_account"`, or `"none"`).  Clients use this to
    /// decide whether to offer the account picker (`prompt=login` forbids it).
    /// Defaults to `"select_account"` when the login is not tied to an OIDC
    /// authorization request.
    pub prompt: String,
    /// The authorization server determined that the selected session must be
    /// authenticated again because it does not satisfy `max_age` or `acr_values`.
    pub requires_reauthentication: bool,
    /// Identifier supplied by the RP to target the intended account/session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    /// Relative first-party UI URI for the next credential challenge. The
    /// authorization server owns this policy decision; the UI only follows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_uri: Option<String>,
    /// Credential the user must add in the `mfa_enrollment_required` phase:
    /// `otp`, or `passkey` when the request requires `phr`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_method: Option<CredentialType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<Vec<String>>,
    /// When another sign-in email may be requested, once one has been sent
    /// for this login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_code_resend_available_at: Option<DateTime<Utc>>,
    /// Whether the password step offers to reset a forgotten password by
    /// email. Offered for every identifier while the account is concealed.
    pub password_reset_available: bool,
    /// When another password reset email may be requested, once one has been
    /// sent for this login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_reset_resend_available_at: Option<DateTime<Utc>>,
    /// Whether the identifier step offers creating an account.
    pub registration_available: bool,
    /// When another registration email may be requested, once one has been
    /// sent for this login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_resend_available_at: Option<DateTime<Utc>>,
    /// Absolute OP `/oauth2/continue?login_id=X` URI, present only when authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_uri: Option<String>,
}

/// `POST /api/auth/login/restart` request.
#[derive(Debug, Deserialize)]
pub struct RestartLoginRequest {
    /// Encrypted login.oid for the challenge that can no longer continue.
    pub id: String,
}

/// `POST /api/auth/login/restart` response.
#[derive(Debug, Serialize)]
pub struct RestartLoginResponse {
    /// Encrypted oid of the newly-created login record.
    pub id: String,
}

/// `POST /api/auth/login/switch` request.
#[derive(Debug, Deserialize)]
pub struct SwitchLoginRequest {
    /// Encrypted login.oid currently bound to the account being replaced.
    pub id: String,
}

/// `POST /api/auth/login/switch` response.
#[derive(Debug, Serialize)]
pub struct SwitchLoginResponse {
    /// Encrypted oid of the same login record, now reset to identifier entry.
    pub id: String,
}

/// User information displayed during the first-party login flow.
#[derive(Debug, Serialize)]
pub struct UserDisplayInfo {
    /// Full email address.
    pub email: String,
    /// User display name.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

// ─── Challenge Step ──────────────────────────────────────────────────────────

/// `POST /api/auth/login/email-code` request.
#[derive(Debug, Deserialize)]
pub struct EmailCodeRequest {
    /// Encrypted login.oid from the identifier step.
    pub id: String,
    /// Locales of the page that asked, most preferred first.
    #[serde(default)]
    pub locales: Vec<String>,
}

/// `POST /api/auth/login/email-code` response. The same whether or not the
/// identifier matched an account that can receive email.
#[derive(Debug, Serialize)]
pub struct EmailCodeResponse {
    pub status: &'static str,
    pub expires_at: DateTime<Utc>,
    pub resend_available_at: DateTime<Utc>,
}

/// `POST /api/auth/login/password-change` request.
#[derive(Debug, Deserialize)]
pub struct RequiredPasswordChangeRequest {
    /// Encrypted login.oid held at a required password change.
    pub id: String,
    pub new_password: String,
}

/// `POST /api/auth/login/password-reset/check` request.
#[derive(Debug, Deserialize)]
pub struct PasswordResetCheckRequest {
    /// Encrypted login.oid the reset link belongs to.
    pub id: String,
    /// The token of the emailed reset link.
    pub token: String,
}

/// `POST /api/auth/login/password-reset/confirm` request.
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirmRequest {
    /// Encrypted login.oid the reset link belongs to.
    pub id: String,
    /// The token of the emailed reset link.
    pub token: String,
    pub new_password: String,
}

/// `POST /api/auth/login/registration` request.
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    /// Encrypted login.oid of the identifier step.
    pub id: String,
    pub email: String,
    /// Locales of the page that asked, most preferred first.
    #[serde(default)]
    pub locales: Vec<String>,
}

/// `POST /api/auth/login/registration/check` request.
#[derive(Debug, Deserialize)]
pub struct RegistrationCheckRequest {
    /// Encrypted login.oid the registration link belongs to.
    pub id: String,
    /// The token of the emailed registration link.
    pub token: String,
}

/// `POST /api/auth/login/registration/check` response.
#[derive(Debug, Serialize)]
pub struct RegistrationCheckResponse {
    pub status: &'static str,
    /// The address the link verifies.
    pub email: String,
}

/// `POST /api/auth/login/registration/confirm` request. Not `Debug`: it
/// carries the new password.
#[derive(Deserialize)]
pub struct RegistrationConfirmRequest {
    /// Encrypted login.oid the registration link belongs to.
    pub id: String,
    /// The token of the emailed registration link.
    pub token: String,
    pub username: String,
    pub new_password: String,
}

/// `POST /api/auth/login/password-reset/check` and `/confirm` response.
#[derive(Debug, Serialize)]
pub struct PasswordResetStatusResponse {
    pub status: &'static str,
}

/// `POST /api/auth/login/challenge` request.
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    /// Encrypted login.oid from the identifier step.
    pub id: String,
    /// Credential type, e.g. `"password"`.
    pub credential_type: CredentialType,
    /// Credential value (plaintext password, etc.).
    pub credential: String,
}

/// `POST /api/auth/login/challenge` response (success).
///
/// When `status` is `"mfa_required"` the `session` field is `None` — the
/// client must call the challenge endpoint again with `credential_type = "otp"`
/// or `credential_type = "recovery_code"`.
///
/// When `status` is `"authenticated"` the `session` field is populated and
/// the `sessions` field contains the updated protected session ID list.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_credential_type: Option<CredentialType>,
    /// `"authenticated"`, `"mfa_required"`, `"mfa_enrollment_required"` or
    /// `"password_change_required"` (then `continue_uri` leads to the change).
    pub status: LoginStatus,
    /// Credential to enroll; present only when `status ==
    /// "mfa_enrollment_required"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_method: Option<CredentialType>,
    /// Present only when `status == "authenticated"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
    /// Authentication Context Class Reference granted for the new session.
    /// Present only when `status == "authenticated"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// `/oauth2/continue?login_id=X` — present only when `status == "authenticated"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_uri: Option<String>,
    /// Complete protected session ID list after authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<String>>,
}

// ─── Progressive MFA Enrollment ──────────────────────────────────────────────

/// `POST /api/auth/login/mfa-enrollment` request.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollmentRequest {
    /// Encrypted login.oid in the `mfa_enrollment_required` phase.
    pub id: String,
}

/// `POST /api/auth/login/mfa-enrollment/algorithm` request.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollmentAlgorithmRequest {
    pub id: String,
    pub algorithm: OtpAlgorithm,
}

/// `POST /api/auth/login/mfa-enrollment/confirm` request.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollmentConfirmRequest {
    pub id: String,
    /// Current code from the newly configured authenticator.
    pub code: String,
}

/// The pending TOTP enrollment bound to a login. Confirmation is answered
/// with a [`ChallengeResponse`].
#[derive(Debug, Serialize)]
pub struct MfaEnrollmentResponse {
    pub secret: String,
    pub otp_auth_uri: String,
    /// One-time recovery codes to save before confirming; empty when the
    /// user already has recovery codes.
    pub recovery_codes: Vec<String>,
    pub algorithm: OtpAlgorithm,
    pub expires_at: DateTime<Utc>,
}

/// `POST /api/auth/login/passkey-enrollment` response: registration options
/// for a `phr` interaction and the recovery codes to save first.
#[derive(Serialize)]
pub struct PasskeyEnrollmentResponse {
    pub options: PasskeyOptions,
    /// Empty when the user already has recovery codes.
    pub recovery_codes: Vec<String>,
}

/// `POST /api/auth/login/passkey-enrollment/confirm` request. Confirmation
/// is answered with a [`ChallengeResponse`] asking for the new passkey.
#[derive(Deserialize)]
pub struct PasskeyEnrollmentConfirmRequest {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub registration: PasskeyAssertion,
}

// ─── Common Types ────────────────────────────────────────────────────────────

/// Session summary.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    /// Data-protected session.oid, externally named `id`.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}
