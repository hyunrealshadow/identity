//! Mapping user profile data to standard claims.

use identity_domain::user::User;
use serde::Serialize;

use super::UserInfoClaims;

/// End-user's preferred postal address.
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
    fn from_user(user: &User) -> Option<Self> {
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

impl UserInfoClaims {
    pub fn from_user(user: &User) -> Self {
        Self::from_user_with_profile_base(user, "https://identity.local")
    }

    pub fn from_user_with_profile_base(user: &User, profile_base_url: &str) -> Self {
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
