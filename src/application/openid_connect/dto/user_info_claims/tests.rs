use chrono::{TimeZone, Utc};
use identity_domain::{
    openid_connect::{ClaimsRequest, ScopeSet},
    user::{User, UserOid},
};
use serde_json::{Value, from_value, json};
use uuid::Uuid;

use super::*;

fn claims_request(value: Value) -> ClaimsRequest {
    from_value(value).unwrap()
}

#[test]
fn from_user_creates_claims_from_user_model() {
    let user_oid = Uuid::new_v4();
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
        theme: None,
        preferred_mfa_method: Default::default(),
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
        created_at: Utc::now(),
        updated_at: Some(Utc::now()),
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
        updated_at: Some(Utc::now()),
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
    let claims_request = claims_request(json!({
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
    let claims_request = claims_request(json!({
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
    let claims_request = claims_request(json!({
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
    let claims_request = claims_request(json!({
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
fn scoped_standard_claims_follows_scope_and_excludes_sub() {
    let user = full_profile_user();
    let scope = ScopeSet::parse("profile email").unwrap();

    let claims = scoped_standard_claims(&user, &scope, None, "https://issuer.example.com");

    assert!(!claims.contains_key("sub"));
    assert_eq!(claims["name"], json!("John Doe"));
    assert_eq!(claims["email"], json!("john@example.com"));
    assert_eq!(claims["email_verified"], json!(true));
    // phone/address claims need their own scopes
    assert!(!claims.contains_key("phone_number"));
    assert!(!claims.contains_key("address"));
}

#[test]
fn scoped_standard_claims_without_scope_returns_nothing_but_sub_is_excluded() {
    let user = full_profile_user();
    let scope = ScopeSet::parse("openid").unwrap();

    let claims = scoped_standard_claims(&user, &scope, None, "https://issuer.example.com");

    assert!(claims.is_empty());
}

#[test]
fn scoped_profile_claims_convert_update_time_to_unix_seconds() {
    let mut user = full_profile_user();
    user.updated_at = Some(Utc.timestamp_opt(1_700_000_000, 123_000_000).unwrap());
    let profile = ScopeSet::parse("openid profile").unwrap();
    let claims = scoped_standard_claims(&user, &profile, None, "https://issuer.example.com");
    assert_eq!(claims["updated_at"].as_i64(), Some(1_700_000_000));

    let openid = ScopeSet::parse("openid").unwrap();
    let claims = scoped_standard_claims(&user, &openid, None, "https://issuer.example.com");
    assert!(!claims.contains_key("updated_at"));
}

fn full_profile_user() -> User {
    let user_oid = Uuid::new_v4();
    User {
        oid: UserOid::from(user_oid),
        email: "john@example.com".to_string(),
        email_normalized: "john@example.com".to_string(),
        name: "John Doe".to_string(),
        name_normalized: "john doe".to_string(),
        given_name: Some("John".to_string()),
        family_name: Some("Doe".to_string()),
        middle_name: None,
        nickname: Some("johnny".to_string()),
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        theme: None,
        preferred_mfa_method: Default::default(),
        email_verified: true,
        phone_number: Some("+12025550123".to_string()),
        phone_number_verified: Some(true),
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
        created_at: Utc::now(),
        updated_at: None,
    }
}
