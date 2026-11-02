use async_graphql::{
    Context, Enum, ID, InputObject, MaybeUndefined, Object, Result as GraphqlResult,
};
use chrono::{DateTime, Utc};
use identity_application::user::management::UserProfilePatch;
use uuid::Uuid;

use super::access::ensure_user_management_read;

/// Stable user-management ordering. Explicit SDL names keep consumers and the
/// persisted cursor contract independent from Rust identifier conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub(super) enum UserOrder {
    #[graphql(name = "CREATED_AT_ASC")]
    CreatedAtAsc,
    #[graphql(name = "CREATED_AT_DESC")]
    CreatedAtDesc,
    #[graphql(name = "USERNAME_ASC")]
    UsernameAsc,
    #[graphql(name = "USERNAME_DESC")]
    UsernameDesc,
}

impl UserOrder {
    pub(super) const fn default_order() -> Self {
        Self::CreatedAtDesc
    }
}

#[derive(Clone, Default, InputObject)]
pub(super) struct UserFilter {
    #[graphql(validator(chars_max_length = 255))]
    pub query: Option<String>,
    #[graphql(validator(chars_max_length = 64))]
    pub username: Option<String>,
    #[graphql(validator(chars_max_length = 320))]
    pub email: Option<String>,
    pub enabled: Option<bool>,
    pub locked: Option<bool>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

#[derive(Clone, InputObject)]
pub(super) struct UserProfilePatchInput {
    #[graphql(validator(chars_max_length = 255))]
    pub given_name: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub family_name: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub middle_name: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub nickname: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub profile: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub picture: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 2048))]
    pub website: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub gender: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 64))]
    pub birthdate: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub zone_info: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 35))]
    pub locale: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 16))]
    pub theme: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_formatted: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_street_address: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_locality: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_region: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 32))]
    pub address_postal_code: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 255))]
    pub address_country: MaybeUndefined<String>,
}

impl UserProfilePatchInput {
    pub(super) fn into_patch(self) -> UserProfilePatch {
        UserProfilePatch {
            given_name: patch_value(self.given_name),
            family_name: patch_value(self.family_name),
            middle_name: patch_value(self.middle_name),
            nickname: patch_value(self.nickname),
            profile: patch_value(self.profile),
            picture: patch_value(self.picture),
            website: patch_value(self.website),
            gender: patch_value(self.gender),
            birthdate: patch_value(self.birthdate),
            zone_info: patch_value(self.zone_info),
            locale: patch_value(self.locale),
            theme: patch_value(self.theme),
            address_formatted: patch_value(self.address_formatted),
            address_street_address: patch_value(self.address_street_address),
            address_locality: patch_value(self.address_locality),
            address_region: patch_value(self.address_region),
            address_postal_code: patch_value(self.address_postal_code),
            address_country: patch_value(self.address_country),
        }
    }
}

fn patch_value(value: MaybeUndefined<String>) -> Option<Option<String>> {
    match value {
        MaybeUndefined::Undefined => None,
        MaybeUndefined::Null => Some(None),
        MaybeUndefined::Value(value) => Some(Some(value.trim().to_owned())),
    }
}

async fn payload_user<'a>(
    ctx: &Context<'_>,
    user: &'a Option<super::super::account::UserNode>,
) -> GraphqlResult<Option<&'a super::super::account::UserNode>> {
    let Some(user) = user.as_ref() else {
        return Ok(None);
    };
    ensure_user_management_read(ctx, user.oid()).await?;
    Ok(Some(user))
}

#[derive(Clone, InputObject)]
pub(super) struct CreateUserInput {
    #[graphql(validator(chars_min_length = 3, chars_max_length = 64))]
    pub username: String,
    #[graphql(validator(chars_max_length = 320))]
    pub email: String,
    #[graphql(secret, validator(chars_max_length = 1024))]
    pub password: String,
    pub profile: Option<UserProfilePatchInput>,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(super) struct UpdateUserInput {
    pub id: ID,
    #[graphql(validator(chars_min_length = 3, chars_max_length = 64))]
    pub username: MaybeUndefined<String>,
    #[graphql(validator(chars_max_length = 320))]
    pub email: MaybeUndefined<String>,
    pub profile: Option<UserProfilePatchInput>,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(super) struct UserStateInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(super) struct UnlockUserInput {
    pub id: ID,
    pub expected_version: Uuid,
    #[graphql(default, validator(chars_max_length = 1000))]
    pub reason: String,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(super) fn normalize_reason(reason: &str) -> Option<String> {
    let reason = reason.trim();
    if reason.chars().count() > 1000 {
        None
    } else {
        Some(reason.to_owned())
    }
}

pub(super) fn optional_identifier(
    value: MaybeUndefined<String>,
) -> Result<Option<String>, InvalidNullIdentifier> {
    match value {
        MaybeUndefined::Undefined => Ok(None),
        MaybeUndefined::Null => Err(InvalidNullIdentifier),
        MaybeUndefined::Value(value) => Ok(Some(value)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InvalidNullIdentifier;

pub(super) struct CreateUserPayload {
    user_id: ID,
    version: Uuid,
    user: Option<super::super::account::UserNode>,
    client_mutation_id: Option<String>,
}

impl CreateUserPayload {
    pub(super) fn new(
        user: identity_domain::user::User,
        client_mutation_id: Option<String>,
    ) -> Self {
        let version = user.version;
        Self {
            user_id: super::super::account::user_global_id(&user),
            version,
            user: Some(super::super::account::UserNode::managed(user)),
            client_mutation_id,
        }
    }
}

#[Object(name = "CreateUserPayload")]
impl CreateUserPayload {
    async fn user_id(&self) -> &ID {
        &self.user_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn user(
        &self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<Option<&super::super::account::UserNode>> {
        payload_user(ctx, &self.user).await
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(super) struct UpdateUserPayload {
    user_id: ID,
    version: Uuid,
    user: Option<super::super::account::UserNode>,
    client_mutation_id: Option<String>,
}

impl UpdateUserPayload {
    pub(super) fn new(
        user: identity_domain::user::User,
        client_mutation_id: Option<String>,
    ) -> Self {
        let version = user.version;
        Self {
            user_id: super::super::account::user_global_id(&user),
            version,
            user: Some(super::super::account::UserNode::managed(user)),
            client_mutation_id,
        }
    }
}

#[Object(name = "UpdateUserPayload")]
impl UpdateUserPayload {
    async fn user_id(&self) -> &ID {
        &self.user_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn user(
        &self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<Option<&super::super::account::UserNode>> {
        payload_user(ctx, &self.user).await
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(super) struct UserStatePayload {
    user_id: ID,
    version: Uuid,
    user: Option<super::super::account::UserNode>,
    client_mutation_id: Option<String>,
}

impl UserStatePayload {
    pub(super) fn new(
        user: identity_domain::user::User,
        client_mutation_id: Option<String>,
    ) -> Self {
        let version = user.version;
        Self {
            user_id: super::super::account::user_global_id(&user),
            version,
            user: Some(super::super::account::UserNode::managed(user)),
            client_mutation_id,
        }
    }
}

#[Object(name = "UserStatePayload")]
impl UserStatePayload {
    async fn user_id(&self) -> &ID {
        &self.user_id
    }

    async fn version(&self) -> Uuid {
        self.version
    }

    async fn user(
        &self,
        ctx: &Context<'_>,
    ) -> GraphqlResult<Option<&super::super::account::UserNode>> {
        payload_user(ctx, &self.user).await
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::MaybeUndefined;

    use super::{UserProfilePatchInput, normalize_reason, optional_identifier};

    fn empty_patch() -> UserProfilePatchInput {
        UserProfilePatchInput {
            given_name: MaybeUndefined::Undefined,
            family_name: MaybeUndefined::Undefined,
            middle_name: MaybeUndefined::Undefined,
            nickname: MaybeUndefined::Undefined,
            profile: MaybeUndefined::Undefined,
            picture: MaybeUndefined::Undefined,
            website: MaybeUndefined::Undefined,
            gender: MaybeUndefined::Undefined,
            birthdate: MaybeUndefined::Undefined,
            zone_info: MaybeUndefined::Undefined,
            locale: MaybeUndefined::Undefined,
            theme: MaybeUndefined::Undefined,
            address_formatted: MaybeUndefined::Undefined,
            address_street_address: MaybeUndefined::Undefined,
            address_locality: MaybeUndefined::Undefined,
            address_region: MaybeUndefined::Undefined,
            address_postal_code: MaybeUndefined::Undefined,
            address_country: MaybeUndefined::Undefined,
        }
    }

    #[test]
    fn omitted_cleared_and_set_profile_values_keep_their_distinct_meaning() {
        let patch = UserProfilePatchInput {
            given_name: MaybeUndefined::Undefined,
            nickname: MaybeUndefined::Null,
            middle_name: MaybeUndefined::Value("  Ada  ".to_owned()),
            ..empty_patch()
        }
        .into_patch();

        assert_eq!(patch.given_name, None);
        assert_eq!(patch.nickname, Some(None));
        assert_eq!(patch.middle_name, Some(Some("Ada".to_owned())));
    }

    #[test]
    fn theme_stays_a_raw_sparse_string_for_application_normalization() {
        assert_eq!(
            UserProfilePatchInput {
                theme: MaybeUndefined::Value(" dark ".to_owned()),
                ..empty_patch()
            }
            .into_patch()
            .theme,
            Some(Some("dark".to_owned()))
        );
        assert_eq!(
            UserProfilePatchInput {
                theme: MaybeUndefined::Null,
                ..empty_patch()
            }
            .into_patch()
            .theme,
            Some(None)
        );
    }

    #[test]
    fn reason_is_trimmed_and_bounded() {
        assert_eq!(
            normalize_reason("  disable for abuse  ").as_deref(),
            Some("disable for abuse")
        );
        assert_eq!(normalize_reason("   "), Some(String::new()));
        assert_eq!(
            normalize_reason(&"界".repeat(1000)),
            Some("界".repeat(1000))
        );
        assert_eq!(normalize_reason(&"界".repeat(1001)), None);
    }

    #[test]
    fn null_identifier_is_distinct_from_omitted_and_value() {
        assert_eq!(optional_identifier(MaybeUndefined::Undefined), Ok(None));
        assert!(optional_identifier(MaybeUndefined::Null).is_err());
        assert_eq!(
            optional_identifier(MaybeUndefined::Value("ada".to_owned())),
            Ok(Some("ada".to_owned()))
        );
    }
}
