use async_graphql::{ID, InputObject, MaybeUndefined, Object};
use identity_domain::user::User;
use identity_infrastructure::{
    database::repository::user::UserProfilePatch,
    graphql::id::{GlobalId, GlobalIdType},
};
use uuid::Uuid;

pub(crate) struct UserGlobalId;

impl GlobalIdType for UserGlobalId {
    const TYPE_NAME: &'static str = "User";
}

pub(crate) struct UserNode {
    id: ID,
    user: User,
}

impl From<User> for UserNode {
    fn from(user: User) -> Self {
        Self {
            id: GlobalId::<UserGlobalId>::new(Uuid::from(user.oid)).into(),
            user,
        }
    }
}

#[Object(name = "User")]
impl UserNode {
    pub(crate) async fn id(&self) -> &ID {
        &self.id
    }

    async fn username(&self) -> &str {
        &self.user.name
    }

    async fn email(&self) -> &str {
        &self.user.email
    }

    async fn email_verified(&self) -> bool {
        self.user.email_verified
    }

    async fn given_name(&self) -> Option<&str> {
        self.user.given_name.as_deref()
    }

    async fn family_name(&self) -> Option<&str> {
        self.user.family_name.as_deref()
    }

    async fn middle_name(&self) -> Option<&str> {
        self.user.middle_name.as_deref()
    }

    async fn nickname(&self) -> Option<&str> {
        self.user.nickname.as_deref()
    }

    async fn profile(&self) -> Option<&str> {
        self.user.profile.as_deref()
    }

    async fn picture(&self) -> Option<&str> {
        self.user.picture.as_deref()
    }

    async fn website(&self) -> Option<&str> {
        self.user.website.as_deref()
    }

    async fn birthdate(&self) -> Option<&str> {
        self.user.birthdate.as_deref()
    }

    async fn locale(&self) -> Option<&str> {
        self.user.locale.as_deref()
    }

    async fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.user.created_at
    }

    async fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.user.updated_at
    }
}

#[derive(Clone, InputObject)]
pub(super) struct UpdateProfileInput {
    pub given_name: MaybeUndefined<String>,
    pub family_name: MaybeUndefined<String>,
    pub middle_name: MaybeUndefined<String>,
    pub nickname: MaybeUndefined<String>,
    pub profile: MaybeUndefined<String>,
    pub picture: MaybeUndefined<String>,
    pub website: MaybeUndefined<String>,
    pub gender: MaybeUndefined<String>,
    pub birthdate: MaybeUndefined<String>,
    pub zone_info: MaybeUndefined<String>,
    pub locale: MaybeUndefined<String>,
    pub address_formatted: MaybeUndefined<String>,
    pub address_street_address: MaybeUndefined<String>,
    pub address_locality: MaybeUndefined<String>,
    pub address_region: MaybeUndefined<String>,
    pub address_postal_code: MaybeUndefined<String>,
    pub address_country: MaybeUndefined<String>,
    pub client_mutation_id: Option<String>,
}

impl UpdateProfileInput {
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
            address_formatted: patch_value(self.address_formatted),
            address_street_address: patch_value(self.address_street_address),
            address_locality: patch_value(self.address_locality),
            address_region: patch_value(self.address_region),
            address_postal_code: patch_value(self.address_postal_code),
            address_country: patch_value(self.address_country),
        }
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateUsernameInput {
    pub username: String,
    pub client_mutation_id: Option<String>,
}

#[derive(Clone, InputObject)]
pub(crate) struct UpdateEmailInput {
    pub email: String,
    pub client_mutation_id: Option<String>,
}

pub(super) struct UpdateProfilePayload {
    user: UserNode,
    client_mutation_id: Option<String>,
}

impl UpdateProfilePayload {
    pub(super) fn new(user: UserNode, client_mutation_id: Option<String>) -> Self {
        Self {
            user,
            client_mutation_id,
        }
    }
}

#[Object]
impl UpdateProfilePayload {
    async fn user(&self) -> &UserNode {
        &self.user
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

fn patch_value(value: MaybeUndefined<String>) -> Option<Option<String>> {
    match value {
        MaybeUndefined::Undefined => None,
        MaybeUndefined::Null => Some(None),
        MaybeUndefined::Value(value) => Some(Some(value.trim().to_string())),
    }
}
