use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result as GraphqlResult, SimpleObject,
};
use chrono::{DateTime, Utc};
use identity_application::{
    authorization::ManagementTarget,
    key::management::{ManagedKeyFilter, ManagedKeyStatus, ManagedKeyUse, ManagedKeyView},
};
use identity_domain::{authorization::ManagementScope, key::KeyOid};
use identity_infrastructure::graphql::id::{GlobalId, GlobalIdType};

use crate::graphql::schema::{
    access::access, management_guard::ManagementGuard, modules::resource::support::decode_oid,
};

pub(crate) struct KeyGlobalId;

impl GlobalIdType for KeyGlobalId {
    const TYPE_NAME: &'static str = "Key";
}

fn key_global_id(oid: KeyOid) -> ID {
    GlobalId::<KeyGlobalId>::new(oid.0).into()
}

pub(crate) fn decode_key_oid(ctx: &Context<'_>, id: &ID) -> GraphqlResult<KeyOid> {
    decode_oid::<KeyGlobalId>(ctx, id).map(KeyOid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "KeyUse")]
pub(crate) enum KeyUseValue {
    /// Signs tokens; its public part is published in the JWKS.
    Signing,
    /// Protects sessions, tokens and cursors.
    Encryption,
}

impl From<ManagedKeyUse> for KeyUseValue {
    fn from(value: ManagedKeyUse) -> Self {
        match value {
            ManagedKeyUse::Signing => Self::Signing,
            ManagedKeyUse::Encryption => Self::Encryption,
        }
    }
}

impl From<KeyUseValue> for ManagedKeyUse {
    fn from(value: KeyUseValue) -> Self {
        match value {
            KeyUseValue::Signing => Self::Signing,
            KeyUseValue::Encryption => Self::Encryption,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(name = "KeyStatus")]
pub(crate) enum KeyStatusValue {
    /// Used for new signatures or new encryption.
    Active,
    /// Replaced by a successor; still verifies or decrypts until it expires.
    Retired,
    Expired,
    Revoked,
}

impl From<ManagedKeyStatus> for KeyStatusValue {
    fn from(value: ManagedKeyStatus) -> Self {
        match value {
            ManagedKeyStatus::Active => Self::Active,
            ManagedKeyStatus::Retired => Self::Retired,
            ManagedKeyStatus::Expired => Self::Expired,
            ManagedKeyStatus::Revoked => Self::Revoked,
        }
    }
}

impl From<KeyStatusValue> for ManagedKeyStatus {
    fn from(value: KeyStatusValue) -> Self {
        match value {
            KeyStatusValue::Active => Self::Active,
            KeyStatusValue::Retired => Self::Retired,
            KeyStatusValue::Expired => Self::Expired,
            KeyStatusValue::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Default, InputObject)]
pub(crate) struct KeyFilter {
    #[graphql(name = "use")]
    pub key_use: Option<KeyUseValue>,
    #[graphql(validator(max_items = 4))]
    pub statuses: Option<Vec<KeyStatusValue>>,
}

impl KeyFilter {
    pub(crate) fn into_application(self) -> ManagedKeyFilter {
        ManagedKeyFilter {
            key_use: self.key_use.map(Into::into),
            statuses: self
                .statuses
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

pub(crate) struct KeyNode {
    view: ManagedKeyView,
}

impl KeyNode {
    pub(crate) fn new(view: ManagedKeyView) -> Self {
        Self { view }
    }
}

#[Object(name = "Key")]
impl KeyNode {
    async fn id(&self) -> ID {
        key_global_id(self.view.record.oid)
    }

    /// How operators and relying parties identify the key: the `kid` of a
    /// signing key's signing binding, or the key's own UUID.
    async fn key_id(&self) -> String {
        self.view
            .record
            .key_ids
            .first()
            .cloned()
            .unwrap_or_else(|| self.view.record.oid.0.to_string())
    }

    #[graphql(name = "use")]
    async fn key_use(&self) -> KeyUseValue {
        self.view.record.key_use.into()
    }

    async fn status(&self) -> KeyStatusValue {
        self.view.status.into()
    }

    /// Whether this key signs new tokens or protects new data on this instance.
    async fn in_use(&self) -> bool {
        self.view.in_use
    }

    /// JWA algorithms of a signing key, or the cipher of an encryption key.
    async fn algorithms(&self) -> &[String] {
        &self.view.record.algorithms
    }

    /// Published `kid` values of a signing key.
    async fn key_ids(&self) -> &[String] {
        &self.view.record.key_ids
    }

    async fn has_certificate(&self) -> bool {
        self.view.record.has_certificate
    }

    /// The key this one replaced.
    async fn rotated_from_id(&self) -> Option<ID> {
        self.view.record.rotated_from.map(key_global_id)
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.view.record.created_at
    }

    async fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.view.record.expires_at
    }

    async fn rotated_at(&self) -> Option<DateTime<Utc>> {
        self.view.record.rotated_at
    }

    async fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.view.record.revoked_at
    }
}

#[derive(Clone, InputObject)]
pub(crate) struct KeyLifecycleInput {
    pub id: ID,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

pub(crate) struct RotateKeyPayload {
    key: ManagedKeyView,
    successor: ManagedKeyView,
    client_mutation_id: Option<String>,
}

impl RotateKeyPayload {
    pub(crate) fn new(
        key: ManagedKeyView,
        successor: ManagedKeyView,
        client_mutation_id: Option<String>,
    ) -> Self {
        Self {
            key,
            successor,
            client_mutation_id,
        }
    }
}

#[Object]
impl RotateKeyPayload {
    /// The retired key.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRead))
    )]
    async fn key(&self) -> Option<KeyNode> {
        Some(KeyNode::new(self.key.clone()))
    }

    /// The key now in use.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRead))
    )]
    async fn successor(&self) -> Option<KeyNode> {
        Some(KeyNode::new(self.successor.clone()))
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub(crate) struct KeyPayload {
    key: ManagedKeyView,
    client_mutation_id: Option<String>,
}

impl KeyPayload {
    pub(crate) fn new(key: ManagedKeyView, client_mutation_id: Option<String>) -> Self {
        Self {
            key,
            client_mutation_id,
        }
    }
}

#[Object]
impl KeyPayload {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRead))
    )]
    async fn key(&self) -> Option<KeyNode> {
        Some(KeyNode::new(self.key.clone()))
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

/// A JWA algorithm a signing key signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(remote = "identity_domain::key::JwaSigningAlgorithm")]
pub(crate) enum SigningAlgorithm {
    #[graphql(name = "RS256")]
    Rs256,
    #[graphql(name = "RS384")]
    Rs384,
    #[graphql(name = "RS512")]
    Rs512,
    #[graphql(name = "PS256")]
    Ps256,
    #[graphql(name = "PS384")]
    Ps384,
    #[graphql(name = "PS512")]
    Ps512,
    #[graphql(name = "ES256")]
    Es256,
    #[graphql(name = "ES384")]
    Es384,
    #[graphql(name = "ES512")]
    Es512,
    #[graphql(name = "ES256K")]
    Es256k,
    #[graphql(name = "EdDSA")]
    EdDsa,
}

/// A key type this instance generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
#[graphql(remote = "identity_domain::key::AsymmetricKeyAlgorithm")]
pub(crate) enum KeyAlgorithm {
    #[graphql(name = "RSA_2048")]
    Rsa2048,
    #[graphql(name = "RSA_3072")]
    Rsa3072,
    #[graphql(name = "RSA_4096")]
    Rsa4096,
    #[graphql(name = "ECDSA_P256")]
    EcdsaP256,
    #[graphql(name = "ECDSA_P384")]
    EcdsaP384,
    #[graphql(name = "ECDSA_P521")]
    EcdsaP521,
    #[graphql(name = "ECDSA_SECP256K1")]
    EcdsaSecp256k1,
    #[graphql(name = "ED25519")]
    Ed25519,
    #[graphql(name = "ED448")]
    Ed448,
    #[graphql(name = "X25519")]
    X25519,
    #[graphql(name = "X448")]
    X448,
}

#[derive(Clone, InputObject)]
pub(crate) struct CreateSigningKeyInput {
    pub algorithm: SigningAlgorithm,
    /// A key the algorithm signs with, from `signingKeyAlgorithms`. Needed
    /// only where it offers several (EdDSA); omitted selects its default.
    pub key_algorithm: Option<KeyAlgorithm>,
    #[graphql(validator(chars_max_length = 255))]
    pub client_mutation_id: Option<String>,
}

/// An algorithm a new signing key can sign with, and one key it can use.
#[derive(SimpleObject)]
pub(crate) struct SigningKeyAlgorithm {
    algorithm: SigningAlgorithm,
    key_algorithm: KeyAlgorithm,
    /// The key as an operator reads it, such as `ECDSA P-256` or `RSA 3072`.
    key_name: &'static str,
}

impl
    From<(
        identity_domain::key::JwaSigningAlgorithm,
        identity_domain::key::AsymmetricKeyAlgorithm,
    )> for SigningKeyAlgorithm
{
    fn from(
        (algorithm, key): (
            identity_domain::key::JwaSigningAlgorithm,
            identity_domain::key::AsymmetricKeyAlgorithm,
        ),
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            key_algorithm: key.into(),
            key_name: key.display_name(),
        }
    }
}
