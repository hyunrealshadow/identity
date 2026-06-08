//! UserInfo Claims for OpenID Connect UserInfo endpoint.
//!
//! These claims are defined in OpenID Connect Core 1.0 specification:
//! https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

use identity_domain::openid_connect::{
    ClaimsRequest, ClaimsRequestSection, model::claim::JwtClaimNames,
};

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
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl AddressClaim {
    fn from_user(user: &identity_domain::user::User) -> Option<Self> {
        let claim = Self {
            formatted: user.address_formatted.clone(),
            street_address: user.address_street_address.clone(),
            locality: user.address_locality.clone(),
            region: user.address_region.clone(),
            postal_code: user.address_postal_code.clone(),
            country: user.address_country.clone(),
        };

        claim.has_any_value().then_some(claim)
    }

    fn has_any_value(&self) -> bool {
        self.formatted.is_some()
            || self.street_address.is_some()
            || self.locality.is_some()
            || self.region.is_some()
            || self.postal_code.is_some()
            || self.country.is_some()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserInfoClaims {
    /// Subject - unique identifier for the user (required).
    pub sub: String,

    /// End-user's full name in displayable form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Given name(s) or first name(s) of the end-user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Surname(s) or last name(s) of the end-user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Middle name(s) of the end-user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    /// Casual name of the end-user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    /// URL of the end-user's profile page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// URL of the end-user's profile picture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// URL of the end-user's web page or blog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    /// End-user's gender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    /// End-user's birthday, represented as an ISO 8601 date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,

    /// End-user's time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,

    /// End-user's locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Shorthand name by which the end-user wishes to be referred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    /// End-user's email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// True if the end-user's email address has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// End-user's preferred telephone number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,

    /// True if the end-user's phone number has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    /// End-user's preferred postal address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,

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
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            updated_at: None,
        }
    }

    pub fn from_user(user: &identity_domain::user::User) -> Self {
        Self::from_user_with_profile_base(user, "https://identity.local")
    }

    pub fn from_user_with_profile_base(
        user: &identity_domain::user::User,
        profile_base_url: &str,
    ) -> Self {
        Self {
            sub: user.oid.0.to_string(),
            name: Some(user.name.clone()),
            given_name: user.given_name.clone(),
            family_name: user.family_name.clone(),
            middle_name: user.middle_name.clone(),
            nickname: user.nickname.clone(),
            profile: absolute_profile_url(profile_base_url, user.profile.as_deref()),
            picture: absolute_profile_url(profile_base_url, user.picture.as_deref()),
            website: absolute_profile_url(profile_base_url, user.website.as_deref()),
            gender: user.gender.clone(),
            birthdate: user.birthdate.clone(),
            zoneinfo: user.zoneinfo.clone(),
            locale: user.locale.clone(),
            preferred_username: Some(user.name.clone()),
            email: Some(user.email.clone()),
            email_verified: Some(user.email_verified),
            phone_number: user.phone_number.clone(),
            phone_number_verified: user.phone_number_verified,
            address: AddressClaim::from_user(user),
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

    pub fn apply_scope_filter(
        &mut self,
        scope: &identity_domain::openid_connect::ScopeSet,
        claims_request: Option<&ClaimsRequest>,
    ) {
        self.apply_scope_filter_for_claim_sections(
            scope,
            claims_request,
            &[ClaimsRequestSection::UserInfo],
        );
    }

    pub fn apply_scope_filter_for_id_token(
        &mut self,
        scope: &identity_domain::openid_connect::ScopeSet,
        claims_request: Option<&ClaimsRequest>,
    ) {
        self.apply_scope_filter_for_claim_sections(
            scope,
            claims_request,
            &[ClaimsRequestSection::IdToken],
        );
    }

    fn apply_scope_filter_for_claim_sections(
        &mut self,
        scope: &identity_domain::openid_connect::ScopeSet,
        claims_request: Option<&ClaimsRequest>,
        claim_sections: &[ClaimsRequestSection],
    ) {
        let essential_claims = Self::extract_essential_claims(claims_request, claim_sections);

        if !scope.profile && !essential_claims.contains(&JwtClaimNames::NAME) {
            self.name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::GIVEN_NAME) {
            self.given_name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::FAMILY_NAME) {
            self.family_name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::MIDDLE_NAME) {
            self.middle_name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::NICKNAME) {
            self.nickname = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::PROFILE) {
            self.profile = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::PICTURE) {
            self.picture = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::WEBSITE) {
            self.website = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::GENDER) {
            self.gender = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::BIRTHDATE) {
            self.birthdate = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::ZONEINFO) {
            self.zoneinfo = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::LOCALE) {
            self.locale = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::PREFERRED_USERNAME) {
            self.preferred_username = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::UPDATED_AT) {
            self.updated_at = None;
        }

        if !scope.email && !essential_claims.contains(&JwtClaimNames::EMAIL) {
            self.email = None;
            self.email_verified = None;
        }

        if !scope.phone && !essential_claims.contains(&JwtClaimNames::PHONE_NUMBER) {
            self.phone_number = None;
            self.phone_number_verified = None;
        }

        if !scope.address && !essential_claims.contains(&JwtClaimNames::ADDRESS) {
            self.address = None;
        }
    }

    fn extract_essential_claims(
        claims_request: Option<&ClaimsRequest>,
        claim_sections: &[ClaimsRequestSection],
    ) -> Vec<&'static str> {
        let Some(claims_request) = claims_request else {
            return Vec::new();
        };

        claims_request
            .essential_claim_names(claim_sections)
            .into_iter()
            .filter_map(known_claim_name)
            .collect()
    }
}

fn known_claim_name(name: &str) -> Option<&'static str> {
    match name {
        n if n == JwtClaimNames::NAME => Some(JwtClaimNames::NAME),
        n if n == JwtClaimNames::GIVEN_NAME => Some(JwtClaimNames::GIVEN_NAME),
        n if n == JwtClaimNames::FAMILY_NAME => Some(JwtClaimNames::FAMILY_NAME),
        n if n == JwtClaimNames::MIDDLE_NAME => Some(JwtClaimNames::MIDDLE_NAME),
        n if n == JwtClaimNames::NICKNAME => Some(JwtClaimNames::NICKNAME),
        n if n == JwtClaimNames::PROFILE => Some(JwtClaimNames::PROFILE),
        n if n == JwtClaimNames::PICTURE => Some(JwtClaimNames::PICTURE),
        n if n == JwtClaimNames::WEBSITE => Some(JwtClaimNames::WEBSITE),
        n if n == JwtClaimNames::GENDER => Some(JwtClaimNames::GENDER),
        n if n == JwtClaimNames::BIRTHDATE => Some(JwtClaimNames::BIRTHDATE),
        n if n == JwtClaimNames::ZONEINFO => Some(JwtClaimNames::ZONEINFO),
        n if n == JwtClaimNames::LOCALE => Some(JwtClaimNames::LOCALE),
        n if n == JwtClaimNames::PREFERRED_USERNAME => Some(JwtClaimNames::PREFERRED_USERNAME),
        n if n == JwtClaimNames::EMAIL => Some(JwtClaimNames::EMAIL),
        n if n == JwtClaimNames::PHONE_NUMBER => Some(JwtClaimNames::PHONE_NUMBER),
        n if n == JwtClaimNames::ADDRESS => Some(JwtClaimNames::ADDRESS),
        n if n == JwtClaimNames::UPDATED_AT => Some(JwtClaimNames::UPDATED_AT),
        _ => None,
    }
}

fn absolute_profile_url(profile_base_url: &str, value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.contains("://") {
        return Some(value.to_owned());
    }

    let base = profile_base_url.trim_end_matches('/');
    let path = value.trim_start_matches('/');
    Some(format!("{base}/{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn claims_request(value: serde_json::Value) -> ClaimsRequest {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn new_creates_claims_with_sub_only() {
        let sub = Uuid::new_v4().to_string();
        let claims = UserInfoClaims::new(sub.clone());

        assert_eq!(claims.sub, sub);
        assert_eq!(claims.name, None);
        assert_eq!(claims.given_name, None);
        assert_eq!(claims.family_name, None);
        assert_eq!(claims.preferred_username, None);
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

    use identity_domain::user::{User, UserOid};

    #[test]
    fn from_user_creates_claims_from_user_model() {
        let user_oid = uuid::Uuid::new_v4();
        let user = User {
            oid: UserOid::from(user_oid),
            email: "john@example.com".to_string(),
            email_normalized: "john@example.com".to_string(),
            name: "John Doe".to_string(),
            name_normalized: "john doe".to_string(),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            middle_name: Some("John Doe".to_string()),
            nickname: Some("john".to_string()),
            profile: Some("users/john".to_string()),
            picture: Some("users/john.png".to_string()),
            website: Some("https://example.com".to_string()),
            gender: Some("unspecified".to_string()),
            birthdate: Some("1970-01-01".to_string()),
            zoneinfo: Some("UTC".to_string()),
            locale: Some("en-US".to_string()),
            email_verified: true,
            phone_number: None,
            phone_number_verified: None,
            address_formatted: None,
            address_street_address: None,
            address_locality: None,
            address_region: None,
            address_postal_code: None,
            address_country: None,
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
        assert_eq!(claims.given_name, Some("John".to_string()));
        assert_eq!(claims.family_name, Some("Doe".to_string()));
        assert_eq!(claims.middle_name, Some("John Doe".to_string()));
        assert_eq!(claims.nickname, Some("john".to_string()));
        assert_eq!(claims.gender, Some("unspecified".to_string()));
        assert_eq!(claims.birthdate, Some("1970-01-01".to_string()));
        assert_eq!(claims.zoneinfo, Some("UTC".to_string()));
        assert_eq!(claims.locale, Some("en-US".to_string()));
        assert_eq!(claims.preferred_username, Some("John Doe".to_string()));
        assert!(claims.profile.is_some());
        assert!(claims.picture.is_some());
        assert!(claims.website.is_some());
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

    use identity_domain::openid_connect::ScopeSet;

    fn full_profile_claims() -> UserInfoClaims {
        UserInfoClaims {
            sub: "user-123".to_string(),
            name: Some("John Doe".to_string()),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            middle_name: Some("John Doe".to_string()),
            nickname: Some("john".to_string()),
            profile: Some("https://example.com/john".to_string()),
            picture: Some("https://example.com/john.png".to_string()),
            website: Some("https://example.com".to_string()),
            gender: Some("unspecified".to_string()),
            birthdate: Some("1970-01-01".to_string()),
            zoneinfo: Some("UTC".to_string()),
            locale: Some("en-US".to_string()),
            preferred_username: Some("john".to_string()),
            email: Some("john@example.com".to_string()),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            address: None,
            updated_at: Some(chrono::Utc::now()),
        }
    }

    #[test]
    fn apply_scope_filter_removes_profile_claims_without_profile_scope() {
        let claims = full_profile_claims();

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid email").unwrap();
        filtered.apply_scope_filter(&scope, None);

        assert_eq!(filtered.sub, "user-123");
        assert_eq!(filtered.name, None);
        assert_eq!(filtered.given_name, None);
        assert_eq!(filtered.family_name, None);
        assert_eq!(filtered.middle_name, None);
        assert_eq!(filtered.nickname, None);
        assert_eq!(filtered.profile, None);
        assert_eq!(filtered.picture, None);
        assert_eq!(filtered.website, None);
        assert_eq!(filtered.gender, None);
        assert_eq!(filtered.birthdate, None);
        assert_eq!(filtered.zoneinfo, None);
        assert_eq!(filtered.locale, None);
        assert_eq!(filtered.preferred_username, None);
        assert_eq!(filtered.email, Some("john@example.com".to_string()));
    }

    #[test]
    fn apply_scope_filter_keeps_all_claims_with_all_scopes() {
        let claims = full_profile_claims();

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid profile email").unwrap();
        filtered.apply_scope_filter(&scope, None);

        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.given_name, Some("John".to_string()));
        assert_eq!(filtered.family_name, Some("Doe".to_string()));
        assert_eq!(filtered.middle_name, Some("John Doe".to_string()));
        assert_eq!(filtered.nickname, Some("john".to_string()));
        assert_eq!(
            filtered.profile,
            Some("https://example.com/john".to_string())
        );
        assert_eq!(
            filtered.picture,
            Some("https://example.com/john.png".to_string())
        );
        assert_eq!(filtered.website, Some("https://example.com".to_string()));
        assert_eq!(filtered.gender, Some("unspecified".to_string()));
        assert_eq!(filtered.birthdate, Some("1970-01-01".to_string()));
        assert_eq!(filtered.zoneinfo, Some("UTC".to_string()));
        assert_eq!(filtered.locale, Some("en-US".to_string()));
        assert_eq!(filtered.preferred_username, Some("john".to_string()));
        assert_eq!(filtered.email, Some("john@example.com".to_string()));
    }

    #[test]
    fn apply_scope_filter_removes_email_claims_without_email_scope() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid profile").unwrap();
        filtered.apply_scope_filter(&scope, None);

        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.email, None);
    }

    #[test]
    fn apply_scope_filter_keeps_essential_claim_without_scope() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid").unwrap();
        let claims_request = claims_request(serde_json::json!({
            "userinfo": {
                "name": {"essential": true}
            }
        }));
        filtered.apply_scope_filter(&scope, Some(&claims_request));

        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.email, None);
    }

    #[test]
    fn apply_scope_filter_for_id_token_keeps_id_token_essential_claim_without_scope() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid").unwrap();
        let claims_request = claims_request(serde_json::json!({
            "id_token": {
                "name": {"essential": true}
            }
        }));
        filtered.apply_scope_filter_for_id_token(&scope, Some(&claims_request));

        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.email, None);
    }

    #[test]
    fn apply_scope_filter_ignores_id_token_essential_claim_for_userinfo() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid").unwrap();
        let claims_request = claims_request(serde_json::json!({
            "id_token": {
                "name": {"essential": true}
            }
        }));
        filtered.apply_scope_filter(&scope, Some(&claims_request));

        assert_eq!(filtered.name, None);
        assert_eq!(filtered.email, None);
    }

    #[test]
    fn apply_scope_filter_removes_non_essential_claim_without_scope() {
        let claims = UserInfoClaims::new("user-123".to_string())
            .with_name("John Doe".to_string())
            .with_email("john@example.com".to_string(), true);

        let mut filtered = claims;
        let scope = ScopeSet::parse("openid").unwrap();
        let claims_request = claims_request(serde_json::json!({
            "userinfo": {
                "name": {"essential": false}
            }
        }));
        filtered.apply_scope_filter(&scope, Some(&claims_request));

        assert_eq!(filtered.name, None);
        assert_eq!(filtered.email, None);
    }

    #[test]
    fn apply_scope_filter_keeps_phone_claims_with_phone_scope() {
        let mut claims = full_profile_claims();
        claims.phone_number = Some("+12025550123".to_string());
        claims.phone_number_verified = Some(true);

        let scope = ScopeSet::parse("openid phone").unwrap();
        claims.apply_scope_filter(&scope, None);

        assert_eq!(claims.phone_number.as_deref(), Some("+12025550123"));
        assert_eq!(claims.phone_number_verified, Some(true));
        assert_eq!(claims.email, None);
    }

    #[test]
    fn apply_scope_filter_removes_phone_claims_without_phone_scope() {
        let mut claims = full_profile_claims();
        claims.phone_number = Some("+12025550123".to_string());
        claims.phone_number_verified = Some(true);

        let scope = ScopeSet::parse("openid profile").unwrap();
        claims.apply_scope_filter(&scope, None);

        assert_eq!(claims.phone_number, None);
        assert_eq!(claims.phone_number_verified, None);
    }

    #[test]
    fn serializes_address_object_when_address_scope_is_present() {
        let mut claims = UserInfoClaims::new("user-123".to_string());
        claims.address = Some(AddressClaim {
            formatted: Some("1 Main St\nExample City".to_string()),
            street_address: Some("1 Main St".to_string()),
            locality: Some("Example City".to_string()),
            region: Some("CA".to_string()),
            postal_code: Some("94000".to_string()),
            country: Some("US".to_string()),
        });

        let json = serde_json::to_value(&claims).unwrap();

        assert_eq!(json["address"]["street_address"], "1 Main St");
        assert_eq!(json["address"]["country"], "US");
    }
}
