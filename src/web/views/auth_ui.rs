//! Server-side rendered login UI DTOs.
//!
//! These structs hold data passed to Tera templates for the login flow.

use serde::Serialize;
use uuid::Uuid;

// ─── Shared sub-types ─────────────────────────────────────────────────────────

/// A single active account entry for the account picker.
#[derive(Debug, Serialize)]
pub struct AccountData {
    /// session.oid — carried as the form `session_id` field.
    pub id: Uuid,
    pub name: String,
    pub email: String,
}

// ─── Page data structs ────────────────────────────────────────────────────────

/// Context for `auth/login.html` — account picker + identifier form.
#[derive(Debug, Serialize, Default)]
pub struct IdentifierPageData {
    /// Active accounts to show in the account picker. Empty = show the form
    /// directly (no accounts section rendered by the template).
    pub accounts: Vec<AccountData>,
    /// Pre-fill the identifier input (e.g. on validation error redirect).
    pub identifier: Option<String>,
    /// Encrypted login.oid that this page should advance.
    pub login_id: Option<String>,
    /// Localised error message to show in the error box.
    pub error: Option<String>,
    /// CSRF token echoed into hidden form fields.
    pub csrf_token: String,
}

/// Context for `auth/password.html`.
#[derive(Debug, Serialize)]
pub struct PasswordPageData {
    /// Encrypted login.oid — carried in the hidden form field.
    pub login_id: String,
    /// Original identifier (email/username) — carried in the hidden form field.
    pub identifier: String,
    /// Display name shown in the user info tile.
    pub user_name: String,
    /// Masked email shown in the user info tile.
    pub masked_email: String,
    /// Localised error message to show in the error box.
    pub error: Option<String>,
    /// CSRF token echoed into hidden form fields.
    pub csrf_token: String,
}

/// Context for `auth/otp.html`.
#[derive(Debug, Serialize)]
pub struct OtpPageData {
    /// Encrypted login.oid — carried in the hidden form field.
    pub login_id: String,
    /// Original identifier — carried in the hidden form field.
    pub identifier: String,
    /// Display name shown in the user info tile.
    pub user_name: String,
    /// Masked email shown in the user info tile.
    pub masked_email: String,
    /// Localised error message to show in the error box.
    pub error: Option<String>,
    /// CSRF token echoed into hidden form fields.
    pub csrf_token: String,
}
