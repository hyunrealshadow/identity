//! UserInfo Claims for OpenID Connect UserInfo endpoint.
//!
//! These claims are defined in OpenID Connect Core 1.0 specification:
//! https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

mod filtering;
mod profile;
mod standard;

pub use profile::AddressClaim;
pub use standard::scoped_standard_claims;

#[cfg(test)]
mod tests;

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

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_email(mut self, email: String, verified: bool) -> Self {
        self.email = Some(email);
        self.email_verified = Some(verified);
        self
    }
}
