//! Public command, context and query types for instance user management.
//!
//! The API adapter constructs these values after its InputObject validators and
//! Global-ID decoding. The application service re-validates domain rules and
//! keeps secrets out of `Debug` output.

use std::{
    collections::BTreeSet,
    fmt::{Debug, Formatter, Result as FmtResult},
};

use chrono::{DateTime, Utc};
use identity_domain::{
    authorization::{
        ActorContext, ManagementAuthorizationSnapshot, ManagementScope, PolicyVersion,
    },
    client::model::ClientOid,
    time_zone::TimeZone,
    user::{UserManagementRecord, UserOid, UserTheme},
};
use uuid::Uuid;

use crate::error::{
    AppError,
    codes::{common::CommonErrorCode, user_management::UserManagementErrorCode},
};

/// Immutable request authority accepted by every write method.
///
/// It contains the authenticated actor, the exact management scopes carried by
/// the access token, the non-reusable authorization snapshot from that
/// credential, the issuing client identity and the original derived
/// client-authority fingerprint. The repository re-locks the live issuing
/// client/policy, derives the current fingerprint and re-loads authoritative
/// bindings/grants, policy version and owner facts inside the write
/// transaction; this value is never treated as proof by itself.
#[derive(Debug, Clone)]
pub struct UserManagementAuthority {
    pub actor: ActorContext,
    pub token_scopes: BTreeSet<ManagementScope>,
    pub snapshot: Option<ManagementAuthorizationSnapshot>,
    pub client_oid: ClientOid,
    pub client_policy_version: PolicyVersion,
}

impl UserManagementAuthority {
    #[must_use]
    pub fn new(
        actor: ActorContext,
        token_scopes: BTreeSet<ManagementScope>,
        snapshot: Option<ManagementAuthorizationSnapshot>,
        client_oid: ClientOid,
        client_policy_version: PolicyVersion,
    ) -> Self {
        Self {
            actor,
            token_scopes,
            snapshot,
            client_oid,
            client_policy_version,
        }
    }
}

/// Password input for user creation. It never appears in `Debug` output and is
/// never returned by a service method.
#[derive(Clone)]
pub struct UserPassword(String);

impl UserPassword {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Debug for UserPassword {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("[REDACTED]")
    }
}

/// Sparse management profile patch. `None` preserves, `Some(None)` clears and
/// `Some(Some(value))` sets the field.
///
/// `theme` stays a raw string so normalization/validation happens in the
/// application layer. MFA preference is intentionally absent: management
/// updates cannot override a user's preferred factor.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserProfilePatch {
    pub given_name: Option<Option<String>>,
    pub family_name: Option<Option<String>>,
    pub middle_name: Option<Option<String>>,
    pub nickname: Option<Option<String>>,
    pub profile: Option<Option<String>>,
    pub picture: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub gender: Option<Option<String>>,
    pub birthdate: Option<Option<String>>,
    pub zone_info: Option<Option<String>>,
    pub locale: Option<Option<String>>,
    pub theme: Option<Option<String>>,
    pub address_formatted: Option<Option<String>>,
    pub address_street_address: Option<Option<String>>,
    pub address_locality: Option<Option<String>>,
    pub address_region: Option<Option<String>>,
    pub address_postal_code: Option<Option<String>>,
    pub address_country: Option<Option<String>>,
}

impl UserProfilePatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Create command after GraphQL shape validation.
#[derive(Debug, Clone)]
pub struct CreateUserCommand {
    pub username: String,
    pub email: String,
    pub password: UserPassword,
    pub profile: UserProfilePatch,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

/// Sparse update command. Omitted username/email preserve the current value.
#[derive(Debug, Clone)]
pub struct UpdateUserCommand {
    pub user_oid: UserOid,
    pub username: Option<String>,
    pub email: Option<String>,
    pub profile: UserProfilePatch,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

/// Shared shape for enable/disable/unlock. Unlock does not enable a user.
#[derive(Debug, Clone)]
pub struct UserStateCommand {
    pub user_oid: UserOid,
    pub expected_version: Uuid,
    pub reason: String,
    pub client_mutation_id: Option<String>,
}

/// List filter. All strings are free-form and treated literally, never as SQL
/// wildcards.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserFilter {
    pub query: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub enabled: Option<bool>,
    pub locked: Option<bool>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserOrder {
    CreatedAtAsc,
    CreatedAtDesc,
    UsernameAsc,
    UsernameDesc,
}

impl Default for UserOrder {
    fn default() -> Self {
        Self::CreatedAtDesc
    }
}

impl UserOrder {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CreatedAtAsc => 0,
            Self::CreatedAtDesc => 1,
            Self::UsernameAsc => 2,
            Self::UsernameDesc => 3,
        }
    }

    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreatedAtAsc),
            1 => Some(Self::CreatedAtDesc),
            2 => Some(Self::UsernameAsc),
            3 => Some(Self::UsernameDesc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_descending(self) -> bool {
        matches!(self, Self::CreatedAtDesc | Self::UsernameDesc)
    }
}

/// Normalized page request. `first`/`last` accept only 1..=100 and default to
/// 20 when neither is supplied.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserPageRequest {
    pub filter: UserFilter,
    pub order: UserOrder,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

/// One management list item with its protected cursor.
#[derive(Debug, Clone)]
pub struct UserManagementPageItem {
    pub record: UserManagementRecord,
    pub cursor: String,
}

/// Relay-style page with accurate boundary flags and no fabricated count.
#[derive(Debug, Clone)]
pub struct UserManagementPage {
    pub items: Vec<UserManagementPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

/// Bundle returned by the service after a successful mutation.
pub type UserManagementMutationResult = UserManagementRecord;

/// Parsed theme for the domain patch.
pub(crate) fn parse_theme(
    value: Option<Option<String>>,
) -> Result<Option<Option<UserTheme>>, crate::error::AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        None => Ok(Some(None)),
        Some(raw) => raw
            .trim()
            .parse::<UserTheme>()
            .map(Some)
            .map(Some)
            .map_err(|_| {
                crate::error::AppError::from_code(
                    crate::error::codes::user_management::UserManagementErrorCode::ValidationFailed,
                )
                .with_field_error(
                    "theme",
                    crate::error::AppError::from_code(
                        crate::error::codes::user_management::UserManagementErrorCode::InvalidTheme,
                    ),
                )
            }),
    }
}

/// Omitted stays omitted, null clears, empty/whitespace clears, and a valid
/// IANA identifier is stored under its canonical name.
fn normalize_zone_info(
    zone_info: Option<Option<String>>,
) -> Result<Option<Option<String>>, AppError> {
    let Some(value) = zone_info else {
        return Ok(None);
    };
    let Some(raw) = value else {
        return Ok(Some(None));
    };
    TimeZone::profile_patch_value(&raw)
        .map(Some)
        .map_err(|_| invalid_time_zone())
}

fn invalid_time_zone() -> AppError {
    AppError::from_code(UserManagementErrorCode::ValidationFailed).with_field_error(
        "zoneInfo",
        AppError::from_code(CommonErrorCode::InvalidTimeZone),
    )
}

/// Convert the management patch into the existing domain patch.
pub(crate) fn domain_profile_patch(
    patch: &UserProfilePatch,
) -> Result<identity_domain::user::repository::UserProfilePatch, AppError> {
    Ok(identity_domain::user::repository::UserProfilePatch {
        given_name: patch.given_name.clone(),
        family_name: patch.family_name.clone(),
        middle_name: patch.middle_name.clone(),
        nickname: patch.nickname.clone(),
        profile: patch.profile.clone(),
        picture: patch.picture.clone(),
        website: patch.website.clone(),
        gender: patch.gender.clone(),
        birthdate: patch.birthdate.clone(),
        zone_info: normalize_zone_info(patch.zone_info.clone())?,
        locale: patch.locale.clone(),
        theme: parse_theme(patch.theme.clone())?,
        preferred_mfa_method: None,
        address_formatted: patch.address_formatted.clone(),
        address_street_address: patch.address_street_address.clone(),
        address_locality: patch.address_locality.clone(),
        address_region: patch.address_region.clone(),
        address_postal_code: patch.address_postal_code.clone(),
        address_country: patch.address_country.clone(),
    })
}

/// User management record, re-exported for adapter convenience.
pub type UserRecord = UserManagementRecord;

#[cfg(test)]
mod tests {
    use super::{UserProfilePatch, domain_profile_patch};

    fn patch_with_zone(zone_info: Option<Option<String>>) -> UserProfilePatch {
        UserProfilePatch {
            zone_info,
            ..Default::default()
        }
    }

    #[test]
    fn zone_info_patch_preserves_omission_clears_empty_and_canonicalizes_valid_input() {
        assert_eq!(
            domain_profile_patch(&patch_with_zone(None))
                .unwrap()
                .zone_info,
            None
        );
        assert_eq!(
            domain_profile_patch(&patch_with_zone(Some(None)))
                .unwrap()
                .zone_info,
            Some(None)
        );
        assert_eq!(
            domain_profile_patch(&patch_with_zone(Some(Some(String::new()))))
                .unwrap()
                .zone_info,
            Some(None)
        );
        assert_eq!(
            domain_profile_patch(&patch_with_zone(Some(Some(" \t ".to_owned()))))
                .unwrap()
                .zone_info,
            Some(None)
        );
        assert_eq!(
            domain_profile_patch(&patch_with_zone(Some(Some("asia/tokyo".to_owned()))))
                .unwrap()
                .zone_info,
            Some(Some("Asia/Tokyo".to_owned()))
        );
    }

    #[test]
    fn invalid_zone_info_is_a_localized_zone_info_field_error() {
        let error =
            domain_profile_patch(&patch_with_zone(Some(Some("+02:00".to_owned())))).unwrap_err();

        assert_eq!(error.code(), 16000);
        let field = &error.validation().unwrap().fields()[0];
        assert_eq!(field.field(), "zoneInfo");
        assert_eq!(field.code(), 10010);
    }
}
