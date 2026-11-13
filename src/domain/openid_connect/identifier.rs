//! OAuth 2.0 / OpenID Connect identifiers presented as Global IDs.
//!
//! `client_id`, a public `sub`, `jti`, `kid` and `management_grant_oid` (a
//! user) name the same objects GraphQL exposes, so they use the same encoding
//! and object kinds. Pairwise subjects remain unlinkable hashes and are never
//! Global IDs. `sid` stays a
//! purpose-bound, data-protected session handle because browsers present it
//! as a credential.

use uuid::Uuid;

use crate::global_id::{self, InvalidGlobalId, kind};

/// The OAuth `client_id` of a client.
#[must_use]
pub fn client_id(client_oid: impl Into<Uuid>) -> String {
    global_id::encode::<kind::Client>(client_oid)
}

pub fn parse_client_id(value: &str) -> Result<Uuid, InvalidGlobalId> {
    global_id::decode::<kind::Client>(value)
}

/// The public subject identifier (`sub`) of a user.
#[must_use]
pub fn user_subject(user_oid: impl Into<Uuid>) -> String {
    global_id::encode::<kind::User>(user_oid)
}

pub fn parse_user_subject(value: &str) -> Result<Uuid, InvalidGlobalId> {
    global_id::decode::<kind::User>(value)
}

/// The `jti` of an issued access token.
#[must_use]
pub fn access_token_id(access_token_oid: impl Into<Uuid>) -> String {
    global_id::encode::<kind::AccessToken>(access_token_oid)
}

pub fn parse_access_token_id(value: &str) -> Result<Uuid, InvalidGlobalId> {
    global_id::decode::<kind::AccessToken>(value)
}

/// The `jti` of a logout token, which names no stored object.
#[must_use]
pub fn logout_token_id(token_oid: impl Into<Uuid>) -> String {
    global_id::encode::<kind::LogoutToken>(token_oid)
}

/// The JWK `kid` of a published key binding.
#[must_use]
pub fn key_id(key_jwk_oid: impl Into<Uuid>) -> String {
    global_id::encode::<kind::KeyJwk>(key_jwk_oid)
}

pub fn parse_key_id(value: &str) -> Result<Uuid, InvalidGlobalId> {
    global_id::decode::<kind::KeyJwk>(value)
}
