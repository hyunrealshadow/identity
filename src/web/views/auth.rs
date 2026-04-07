//! Authentication API request and response DTOs.
//!
//! All external `id` fields are [`Uuid`] values sourced from the
//! corresponding entity's `oid` column.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::user::model::CredentialType;

// ─── Common Error Response ───────────────────────────────────────────────────

/// Unified error response body.
#[derive(Debug, Serialize)]
pub struct BusinessErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    /// Machine-readable numeric error code, e.g. `2001`.
    pub code: u32,
    /// Localized human-readable message.
    pub message: String,
}

impl BusinessErrorResponse {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code,
                message: message.into(),
            },
        }
    }
}

// ─── Account Picker ──────────────────────────────────────────────────────────

/// `GET /api/auth/sessions/active` response.
#[derive(Debug, Serialize)]
pub struct ActiveAccountsResponse {
    pub accounts: Vec<AccountItem>,
}

/// A single logged-in account entry.
#[derive(Debug, Serialize)]
pub struct AccountItem {
    /// session.oid, externally named `id`.
    pub id: Uuid,
    /// User display name.
    pub name: String,
    /// Full email (not masked — this is the user's own account list).
    pub email: String,
    /// Last active timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<DateTime<Utc>>,
}

// ─── Select Existing Account ─────────────────────────────────────────────────

/// `POST /api/auth/login/select` request.
#[derive(Debug, Deserialize)]
pub struct SelectAccountRequest {
    /// session.oid to select.
    pub id: Uuid,
}

/// `POST /api/auth/login/select` response (success).
#[derive(Debug, Serialize)]
pub struct SelectAccountResponse {
    pub status: &'static str,
    pub session: SessionInfo,
}

// ─── Identifier Step ─────────────────────────────────────────────────────────

/// `POST /api/auth/login/identifier` request.
#[derive(Debug, Deserialize)]
pub struct IdentifierRequest {
    /// Email or username.
    pub identifier: String,
}

/// `POST /api/auth/login/identifier` response (success).
#[derive(Debug, Serialize)]
pub struct IdentifierResponse {
    /// login.oid — must be carried to subsequent steps.
    pub id: Uuid,
    /// Current login flow status.
    pub status: &'static str,
    /// Credential types available for this user, e.g. `["password"]`.
    pub credential_types: Vec<CredentialType>,
    /// Masked user display info.
    pub user: UserDisplayInfo,
}

/// Masked user info (prevents information leakage).
#[derive(Debug, Serialize)]
pub struct UserDisplayInfo {
    /// Masked email, e.g. `"u***@example.com"`.
    pub email: String,
    /// User display name.
    pub name: String,
}

// ─── Challenge Step ──────────────────────────────────────────────────────────

/// `POST /api/auth/login/challenge` request.
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    /// login.oid from the identifier step.
    pub id: Uuid,
    /// Credential type, e.g. `"password"`.
    pub credential_type: String,
    /// Credential value (plaintext password, etc.).
    pub credential: String,
}

/// `POST /api/auth/login/challenge` response (success).
///
/// When `status` is `"mfa_required"` the `session` field is `None` — the
/// client must call the challenge endpoint again with `credential_type = "otp"`.
///
/// When `status` is `"authenticated"` the `session` field is populated and
/// the `Set-Cookie` header contains the updated sessions cookie.
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
}

// ─── Common Types ────────────────────────────────────────────────────────────

/// Session summary.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    /// session.oid, externally named `id`.
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Mask an email address: keep the first character and the domain.
///
/// Example: `"user@example.com"` -> `"u***@example.com"`
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];
        if local.is_empty() {
            return email.to_owned();
        }
        let first = &local[..local
            .char_indices()
            .nth(1)
            .map(|(i, _)| i)
            .unwrap_or(local.len())];
        format!("{first}***{domain}")
    } else {
        email.to_owned()
    }
}
