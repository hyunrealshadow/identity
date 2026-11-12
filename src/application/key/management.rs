//! Instance key management: the signing keys behind the published JWKS and
//! the symmetric keys that protect sessions, tokens and cursors.
//!
//! Only metadata leaves this module; private and secret material never does.
//!
//! Lifecycle invariants:
//! - Rotating replaces a key that is in use with a successor of the same
//!   algorithm. The predecessor retires: it keeps verifying signatures or
//!   decrypting existing payloads until it expires.
//! - Signing keys of several algorithms can be active at once; a client that
//!   asks for an algorithm is served by that key, and the newest key signs for
//!   everyone else. Only signing keys are added by hand.
//! - A key in use can be revoked only while another active key of the same
//!   use remains, so every use always keeps a key. Revoking removes the key
//!   from the JWKS, or makes payloads protected by it unreadable, immediately.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::key::{
    AsymmetricKeyAlgorithm, JwaSigningAlgorithm, Key, KeyData, KeyOid, KeyType,
    generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use super::{
    asymmetric::{GeneratedKeyJwk, KeyJwkGenerator},
    rotation::{KeyRotationMaterialGenerator, RotationMaterial},
    runtime::RuntimeKeyRingProvider,
};
use crate::{
    authorization::ManagementAuthorizationError,
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{authorization::AuthorizationErrorCode, instance::InstanceErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
    rbac::{
        RbacManagementAuthority,
        cursor::{PageArguments, RbacPageDirection, RbacSortKey, encode_cursor, prepare_page},
    },
    setting::management::validate_client_mutation_id,
};

pub(crate) const CURSOR_KIND_KEY: u8 = 13;
const KEY_ORDER_CREATED_AT_DESC: u8 = 1;

/// What a key is used for. Asymmetric keys sign tokens; symmetric keys
/// protect data at rest and in transit between requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedKeyUse {
    Signing,
    Encryption,
}

impl ManagedKeyUse {
    #[must_use]
    pub const fn key_type(self) -> KeyType {
        match self {
            Self::Signing => KeyType::Asymmetric,
            Self::Encryption => KeyType::Symmetric,
        }
    }

    #[must_use]
    pub fn from_key_type(value: &KeyType) -> Self {
        match value {
            KeyType::Asymmetric => Self::Signing,
            KeyType::Symmetric => Self::Encryption,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedKeyStatus {
    /// Used for new signatures or new encryption.
    Active,
    /// Replaced by a successor; still verifies or decrypts until it expires.
    Retired,
    Expired,
    Revoked,
}

impl ManagedKeyStatus {
    #[must_use]
    pub fn of(
        now: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        rotated_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> Self {
        if revoked_at.is_some() {
            Self::Revoked
        } else if expires_at.is_some_and(|expires_at| expires_at <= now) {
            Self::Expired
        } else if rotated_at.is_some() {
            Self::Retired
        } else {
            Self::Active
        }
    }
}

/// Key metadata safe to show an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedKeyRecord {
    pub oid: KeyOid,
    pub key_use: ManagedKeyUse,
    /// JWA names for signing keys, the cipher for encryption keys.
    pub algorithms: Vec<String>,
    /// Published `kid` values of a signing key.
    pub key_ids: Vec<String>,
    pub has_certificate: bool,
    pub rotated_from: Option<KeyOid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ManagedKeyRecord {
    #[must_use]
    pub fn status(&self, now: DateTime<Utc>) -> ManagedKeyStatus {
        ManagedKeyStatus::of(now, self.expires_at, self.rotated_at, self.revoked_at)
    }
}

/// A record with the facts that depend on this instance's live key ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedKeyView {
    pub record: ManagedKeyRecord,
    pub status: ManagedKeyStatus,
    /// Whether this key signs new tokens or protects new data right now.
    pub in_use: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ManagedKeyFilter {
    pub key_use: Option<ManagedKeyUse>,
    pub statuses: Vec<ManagedKeyStatus>,
}

#[derive(Debug, Clone, Default)]
pub struct ManagedKeyPageRequest {
    pub filter: ManagedKeyFilter,
    pub first: Option<u32>,
    pub after: Option<String>,
    pub last: Option<u32>,
    pub before: Option<String>,
}

pub struct ManagedKeyQuery {
    pub filter: ManagedKeyFilter,
    pub now: DateTime<Utc>,
    pub direction: RbacPageDirection,
    pub after: Option<(DateTime<Utc>, Uuid)>,
    pub before: Option<(DateTime<Utc>, Uuid)>,
    pub limit: usize,
}

pub struct ManagedKeyPageData {
    pub items: Vec<ManagedKeyRecord>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

pub struct ManagedKeyPageItem {
    pub view: ManagedKeyView,
    pub cursor: String,
}

pub struct ManagedKeyPage {
    pub items: Vec<ManagedKeyPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

#[derive(Debug, Clone)]
pub struct KeyLifecycleCommand {
    pub key_oid: KeyOid,
    pub client_mutation_id: Option<String>,
}

pub struct RotateKeyTransaction {
    pub authority: RbacManagementAuthority,
    pub key_oid: KeyOid,
    pub material: RotationMaterial,
    /// Also revoke the predecessor in the same transaction, for a key that
    /// must stop verifying or decrypting immediately.
    pub revoke_previous: bool,
    pub now: DateTime<Utc>,
}

/// A new, independent key. Its JWK bindings receive their `kid` on insert.
pub struct CreateKeyTransaction {
    pub authority: RbacManagementAuthority,
    pub data: KeyData,
    pub jwks: Vec<GeneratedKeyJwk>,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateSigningKeyCommand {
    pub algorithm: JwaSigningAlgorithm,
    /// Which key the algorithm signs with when it offers several (EdDSA);
    /// `None` selects its default.
    pub key_algorithm: Option<AsymmetricKeyAlgorithm>,
    pub client_mutation_id: Option<String>,
}

/// Every algorithm and key a signing key can be added with, in the order
/// offered. EdDSA appears once per Edwards curve.
#[must_use]
pub fn signing_key_algorithms() -> Vec<(JwaSigningAlgorithm, AsymmetricKeyAlgorithm)> {
    JwaSigningAlgorithm::all()
        .iter()
        .flat_map(|algorithm| {
            algorithm
                .key_algorithms()
                .iter()
                .map(|key| (*algorithm, *key))
        })
        .collect()
}

pub struct RevokeKeyTransaction {
    pub authority: RbacManagementAuthority,
    pub key_oid: KeyOid,
    pub now: DateTime<Utc>,
}

/// The rotated key and its successor.
#[derive(Debug, Clone)]
pub struct KeyRotationResult {
    pub previous: ManagedKeyRecord,
    pub successor: ManagedKeyRecord,
}

#[derive(Debug, Error)]
pub enum KeyManagementRepositoryError {
    #[error("key storage failed")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("management authorization failed")]
    Authorization(#[source] ManagementAuthorizationError),
    #[error("security audit write failed")]
    AuditFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("no recoverable authorization administrator would remain")]
    LastRecoverableAdministrator,
    #[error("key not found")]
    NotFound,
    #[error("key is not in use")]
    NotActive,
    #[error("the last active key of its use cannot be revoked")]
    LastActiveKey,
    #[error("key already revoked")]
    AlreadyRevoked,
}

#[async_trait]
pub trait KeyManagementRepository: Send + Sync {
    async fn count(
        &self,
        filter: ManagedKeyFilter,
        now: DateTime<Utc>,
    ) -> Result<u64, KeyManagementRepositoryError>;

    async fn list(
        &self,
        query: ManagedKeyQuery,
    ) -> Result<ManagedKeyPageData, KeyManagementRepositoryError>;

    async fn find(
        &self,
        oid: KeyOid,
    ) -> Result<Option<ManagedKeyRecord>, KeyManagementRepositoryError>;

    /// Loads the key with its material, for generating a successor only.
    async fn find_material(&self, oid: KeyOid)
    -> Result<Option<Key>, KeyManagementRepositoryError>;

    async fn create(
        &self,
        transaction: CreateKeyTransaction,
    ) -> Result<ManagedKeyRecord, KeyManagementRepositoryError>;

    async fn rotate(
        &self,
        transaction: RotateKeyTransaction,
    ) -> Result<KeyRotationResult, KeyManagementRepositoryError>;

    async fn revoke(
        &self,
        transaction: RevokeKeyTransaction,
    ) -> Result<ManagedKeyRecord, KeyManagementRepositoryError>;
}

pub struct KeyManagementService {
    repository: Arc<dyn KeyManagementRepository>,
    generator: Arc<dyn KeyRotationMaterialGenerator>,
    key_generator: Arc<dyn AsymmetricKeyGenerator>,
    jwk_generator: Arc<dyn KeyJwkGenerator>,
    runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl KeyManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn KeyManagementRepository>,
        generator: Arc<dyn KeyRotationMaterialGenerator>,
        key_generator: Arc<dyn AsymmetricKeyGenerator>,
        jwk_generator: Arc<dyn KeyJwkGenerator>,
        runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            repository,
            generator,
            key_generator,
            jwk_generator,
            runtime_key_ring,
            data_protector,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    fn view(&self, record: ManagedKeyRecord, now: DateTime<Utc>) -> ManagedKeyView {
        let ring = self.runtime_key_ring.current_value();
        let in_use = match record.key_use {
            ManagedKeyUse::Signing => ring
                .signing_key()
                .is_some_and(|key| record.key_ids.contains(&key.key_id)),
            ManagedKeyUse::Encryption => ring
                .data_protection()
                .encrypting_key(now)
                .is_some_and(|key| key.oid == record.oid),
        };
        ManagedKeyView {
            status: record.status(now),
            in_use,
            record,
        }
    }

    #[tracing::instrument(skip_all, name = "key.management.count")]
    pub async fn count(&self, filter: ManagedKeyFilter) -> Result<u64, AppError> {
        self.repository
            .count(normalize_filter(filter), Utc::now())
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "key.management.list")]
    pub async fn list(&self, request: ManagedKeyPageRequest) -> Result<ManagedKeyPage, AppError> {
        let filter = normalize_filter(request.filter);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_KEY,
            KEY_ORDER_CREATED_AT_DESC,
            &filter,
            PageArguments {
                first: request.first,
                after: request.after,
                last: request.last,
                before: request.before,
            },
        )
        .await?;
        let position = |key: Option<RbacSortKey>| -> Result<_, AppError> {
            match key {
                None => Ok(None),
                Some(RbacSortKey::CreatedAt {
                    created_at,
                    tie: crate::rbac::cursor::RbacTie::Oid(oid),
                }) => Ok(Some((created_at, oid))),
                Some(_) => Err(AppError::from_code(
                    crate::error::codes::rbac::RbacErrorCode::InvalidCursor,
                )),
            }
        };
        let now = Utc::now();
        let data = self
            .repository
            .list(ManagedKeyQuery {
                filter,
                now,
                direction: prepared.direction,
                after: position(prepared.after)?,
                before: position(prepared.before)?,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for record in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                CURSOR_KIND_KEY,
                KEY_ORDER_CREATED_AT_DESC,
                &prepared.filter_fingerprint,
                &RbacSortKey::CreatedAt {
                    created_at: record.created_at,
                    tie: crate::rbac::cursor::RbacTie::Oid(Uuid::from(record.oid)),
                },
            )
            .await?;
            items.push(ManagedKeyPageItem {
                view: self.view(record, now),
                cursor,
            });
        }
        Ok(ManagedKeyPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "key.management.find")]
    pub async fn find(&self, oid: KeyOid) -> Result<Option<ManagedKeyView>, AppError> {
        let record = self
            .repository
            .find(oid)
            .await
            .map_err(map_repository_error)?;
        Ok(record.map(|record| self.view(record, Utc::now())))
    }

    /// Add an independent signing key with `algorithm`. It becomes the newest
    /// active signing key; existing keys keep signing for clients that ask for
    /// their algorithm.
    #[tracing::instrument(skip_all, name = "key.management.create")]
    pub async fn create_signing_key(
        &self,
        authority: &RbacManagementAuthority,
        command: CreateSigningKeyCommand,
    ) -> Result<ManagedKeyView, AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let algorithm = command.algorithm;
            let key = algorithm
                .key_algorithm_for_new_key(command.key_algorithm)
                .ok_or_else(|| {
                    AppError::from_code(InstanceErrorCode::UnsupportedKeyAlgorithm)
                        .with_param("algorithm", algorithm.as_str())
                        .with_field("keyAlgorithm")
                })?;
            let data = self
                .key_generator
                .generate(&AsymmetricKeySpec::for_signing(algorithm, key))?;
            // Each binding receives its own `kid` when stored. The key signs
            // with the chosen algorithm only.
            let jwks = self.jwk_generator.generate_for(
                &data.private_key,
                "pending",
                None,
                &[algorithm],
            )?;
            let now = Utc::now();
            let record = self
                .repository
                .create(CreateKeyTransaction {
                    authority: authority.clone(),
                    data: KeyData::Asymmetric(data),
                    jwks,
                    now,
                })
                .await
                .map_err(map_repository_error)?;
            self.refresh().await;
            Ok(self.view(record, now))
        }
        .await;
        let mut event = BusinessEvent::business("key.create");
        match &result {
            Ok(view) => {
                event = event.outcome("success").attribute(
                    "key_oid",
                    EventValue::Text(Uuid::from(view.record.oid).to_string()),
                );
            }
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        self.events.emit(event);
        result
    }

    #[tracing::instrument(skip_all, name = "key.management.rotate")]
    pub async fn rotate(
        &self,
        authority: &RbacManagementAuthority,
        command: KeyLifecycleCommand,
    ) -> Result<(ManagedKeyView, ManagedKeyView), AppError> {
        self.replace(authority, command, false).await
    }

    /// Rotate and revoke the predecessor at once: tokens it signed stop
    /// validating, and data it protected can no longer be read.
    #[tracing::instrument(skip_all, name = "key.management.rotate_and_revoke")]
    pub async fn rotate_and_revoke(
        &self,
        authority: &RbacManagementAuthority,
        command: KeyLifecycleCommand,
    ) -> Result<(ManagedKeyView, ManagedKeyView), AppError> {
        self.replace(authority, command, true).await
    }

    async fn replace(
        &self,
        authority: &RbacManagementAuthority,
        command: KeyLifecycleCommand,
        revoke_previous: bool,
    ) -> Result<(ManagedKeyView, ManagedKeyView), AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let previous = self
                .repository
                .find_material(command.key_oid)
                .await
                .map_err(map_repository_error)?
                .ok_or_else(|| AppError::from_code(InstanceErrorCode::KeyNotFound))?;
            // Generation happens outside the transaction; the repository
            // re-checks that the key is still in use before storing it.
            let material = self.generator.generate(&previous)?;
            let now = Utc::now();
            let rotated = self
                .repository
                .rotate(RotateKeyTransaction {
                    authority: authority.clone(),
                    key_oid: command.key_oid,
                    material,
                    revoke_previous,
                    now,
                })
                .await
                .map_err(map_repository_error)?;
            self.refresh().await;
            Ok((
                self.view(rotated.previous, now),
                self.view(rotated.successor, now),
            ))
        }
        .await;
        let name = if revoke_previous {
            "key.rotate_and_revoke"
        } else {
            "key.rotate"
        };
        self.emit(name, command.key_oid, &result);
        result
    }

    #[tracing::instrument(skip_all, name = "key.management.revoke")]
    pub async fn revoke(
        &self,
        authority: &RbacManagementAuthority,
        command: KeyLifecycleCommand,
    ) -> Result<ManagedKeyView, AppError> {
        let result = async {
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;
            let now = Utc::now();
            let record = self
                .repository
                .revoke(RevokeKeyTransaction {
                    authority: authority.clone(),
                    key_oid: command.key_oid,
                    now,
                })
                .await
                .map_err(map_repository_error)?;
            self.refresh().await;
            Ok(self.view(record, now))
        }
        .await;
        self.emit("key.revoke", command.key_oid, &result);
        result
    }

    /// Applies a committed key change on this instance; other instances pick
    /// it up on their next refresh.
    async fn refresh(&self) {
        if let Err(error) = self.runtime_key_ring.refresh_value().await {
            tracing::warn!(error = %error, "failed to refresh key ring after key change");
        }
    }

    fn emit<T>(&self, name: &'static str, oid: KeyOid, result: &Result<T, AppError>) {
        let mut event = BusinessEvent::business(name)
            .attribute("key_oid", EventValue::Text(Uuid::from(oid).to_string()));
        match result {
            Ok(_) => event = event.outcome("success"),
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        self.events.emit(event);
    }
}

fn normalize_filter(mut filter: ManagedKeyFilter) -> ManagedKeyFilter {
    filter.statuses.sort_by_key(|status| *status as u8);
    filter.statuses.dedup();
    filter
}

fn map_repository_error(error: KeyManagementRepositoryError) -> AppError {
    use KeyManagementRepositoryError as Error;
    match error {
        error @ Error::Storage(_) => {
            AppError::from_code(InstanceErrorCode::StorageFailed).with_source(error)
        }
        Error::Authorization(source) => AppError::from(source),
        error @ Error::AuditFailed(_) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(error)
        }
        Error::LastRecoverableAdministrator => {
            AppError::from_code(AuthorizationErrorCode::LastOwnerProtected)
        }
        Error::NotFound => AppError::from_code(InstanceErrorCode::KeyNotFound),
        Error::NotActive => AppError::from_code(InstanceErrorCode::KeyNotCurrent),
        Error::LastActiveKey => AppError::from_code(InstanceErrorCode::LastActiveKey),
        Error::AlreadyRevoked => AppError::from_code(InstanceErrorCode::KeyAlreadyRevoked),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::ManagedKeyStatus;

    #[test]
    fn status_prefers_revocation_then_expiry_then_retirement() {
        let now = chrono::Utc::now();
        let later = Some(now + Duration::days(1));
        let earlier = Some(now - Duration::days(1));
        assert_eq!(
            ManagedKeyStatus::of(now, later, None, None),
            ManagedKeyStatus::Active
        );
        assert_eq!(
            ManagedKeyStatus::of(now, later, earlier, None),
            ManagedKeyStatus::Retired
        );
        assert_eq!(
            ManagedKeyStatus::of(now, earlier, earlier, None),
            ManagedKeyStatus::Expired
        );
        assert_eq!(
            ManagedKeyStatus::of(now, earlier, earlier, earlier),
            ManagedKeyStatus::Revoked
        );
    }
}
