//! Authentication API request and response DTOs.
//!
//! All external `id` fields are encrypted login.oid values.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use identity_domain::user::CredentialType;

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
            },
        }
    }

    pub fn with_fields(mut self, fields: Vec<FieldErrorDetail>) -> Self {
        self.error.fields = fields;
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
    pub status: &'static str,
    /// Credential types available for this user, e.g. `["password"]`.
    pub credential_types: Vec<CredentialType>,
    /// User display info.
    pub user: UserDisplayInfo,
}

#[derive(Debug, Serialize)]
pub struct LoginStatusResponse {
    /// Encrypted login.oid.
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDisplayInfo>,
    /// Credential types available to the bound user. Empty before an account
    /// has been selected.
    pub credential_types: Vec<CredentialType>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<Vec<String>>,
    /// Absolute OP `/oauth2/continue?login_id=X` URI, present only when authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_uri: Option<String>,
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

/// `POST /api/auth/login/challenge` request.
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    /// Encrypted login.oid from the identifier step.
    pub id: String,
    /// Credential type, e.g. `"password"`.
    pub credential_type: String,
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
    /// `"authenticated"` or `"mfa_required"`.
    pub status: &'static str,
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

// ─── Common Types ────────────────────────────────────────────────────────────

/// Session summary.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    /// Data-protected session.oid, externally named `id`.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}
