//! UserInfo Claims for OpenID Connect UserInfo endpoint.
//!
//! These claims are defined in OpenID Connect Core 1.0 specification:
//! https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

fn serialize_datetime_as_unix<S>(
    dt: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => serializer.serialize_i64(dt.timestamp()),
        None => serializer.serialize_none(),
    }
}

/// UserInfo Claims returned from the UserInfo endpoint.
///
/// All fields except `sub` are optional and may be omitted based on
/// the scopes granted and user's profile data.
#[derive(Debug, Clone, Serialize)]
pub struct UserInfoClaims {
    /// Subject - unique identifier for the user (required).
    pub sub: String,

    /// End-user's full name in displayable form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// End-user's email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// True if the end-user's email address has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// Time the end-user's information was last updated.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_datetime_as_unix"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl UserInfoClaims {
    pub fn new(sub: String) -> Self {
        Self {
            sub,
            name: None,
            email: None,
            email_verified: None,
            updated_at: None,
        }
    }

    pub fn from_user(user: &crate::domain::user::User) -> Self {
        Self {
            sub: user.oid.0.to_string(),
            name: Some(user.name.clone()),
            email: Some(user.email.clone()),
            email_verified: Some(user.email_verified),
            updated_at: user.updated_at,
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_email(mut self, email: String, verified: bool) -> Self {
        self.email = Some(email);
        self.email_verified = Some(verified);
        self
    }

    pub fn apply_scope_filter(&mut self, scope: &crate::domain::openid_connect::ScopeSet) {
        if !scope.profile {
            self.name = None;
            self.updated_at = None;
        }

        if !scope.email {
            self.email = None;
            self.email_verified = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn new_creates_claims_with_sub_only() {
        let sub = Uuid::new_v4().to_string();
        let claims = UserInfoClaims::new(sub.clone());

        assert_eq!(claims.sub, sub);
        assert_eq!(claims.name, None);
        assert_eq!(claims.email, None);
        assert_eq!(claims.email_verified, None);
        assert_eq!(claims.updated_at, None);
    }

    #[test]
    fn serializes_sub_as_required_field() {
        let claims = UserInfoClaims::new("user-123".to_string());
        let json = serde_json::to_string(&claims).unwrap();

        assert!(json.contains("\"sub\":\"user-123\""));
    }

    #[test]
    fn skips_none_claims_in_serialization() {
        let claims = UserInfoClaims::new("user-123".to_string());
        let json = serde_json::to_string(&claims).unwrap();

        assert!(!json.contains("name"));
        assert!(!json.contains("email"));
    }

    use crate::domain::user::{User, UserOid};

    #[test]
    fn from_user_creates_claims_from_user_model() {
        let user_oid = uuid::Uuid::new_v4();
        let user = User {
            oid: UserOid::from(user_oid),
            email: "john@example.com".to_string(),
            email_normalized: "john@example.com".to_string(),
            name: "John Doe".to_string(),
            name_normalized: "john doe".to_string(),
            email_verified: true,
            failed_attempts: 0,
            enabled: true,
            locked: false,
            locked_until: None,
            created_at: chrono::Utc::now(),
            updated_at: Some(chrono::Utc::now()),
        };

        let claims = UserInfoClaims::from_user(&user);

        assert_eq!(claims.sub, user_oid.to_string());
        assert_eq!(claims.name, Some("John Doe".to_string()));
        assert_eq!(claims.email, Some("john@example.com".to_string()));
        assert_eq!(claims.email_verified, Some(true));
        assert!(claims.updated_at.is_some());
    }

    #[test]
    fn serializes_all_claims_when_present() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["sub"], "user-123");
        assert_eq!(parsed["name"], "John Doe");
        assert_eq!(parsed["email"], "john@example.com");
        assert_eq!(parsed["email_verified"], true);
    }

    use crate::domain::openid_connect::ScopeSet;

    #[test]
    fn apply_scope_filter_removes_profile_claims_without_profile_scope() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid email").unwrap();
        filtered.apply_scope_filter(&scope);

        assert_eq!(filtered.sub, "user-123");
        assert_eq!(filtered.name, None);
        assert_eq!(filtered.email, Some("john@example.com".to_string()));
    }

    #[test]
    fn apply_scope_filter_keeps_all_claims_with_all_scopes() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid profile email").unwrap();
        filtered.apply_scope_filter(&scope);

        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.email, Some("john@example.com".to_string()));
    }

    #[test]
    fn apply_scope_filter_removes_email_claims_without_email_scope() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid profile").unwrap();
        filtered.apply_scope_filter(&scope);

        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.email, None);
    }
}
