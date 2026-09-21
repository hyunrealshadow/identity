use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::device::{
    DeviceAuthorizationApproval, DeviceAuthorizationRequestData, DevicePollOutcome,
};
use super::model::{
    ClientAuthorization, ClientAuthorizationData, ClientAuthorizationType, ConsentState,
    SelectionSource,
};
use crate::auth::model::SessionOid;
use crate::client::model::ClientOid;
use crate::openid_connect::ScopeSet;

#[async_trait]
pub trait ClientAuthorizationRepository: Send + Sync {
    async fn create(
        &self,
        client_oid: ClientOid,
        data: ClientAuthorizationData,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError>;

    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError>;

    async fn update_authorization_request_selection(
        &self,
        oid: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn record_authorization_request_consent(
        &self,
        oid: Uuid,
        consent_state: ConsentState,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn has_user_consent(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
        requested_scope: &ScopeSet,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn mark_authorization_request_completed(
        &self,
        oid: Uuid,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;

    async fn revoke_access_tokens_for_authorization_code(
        &self,
        authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError>;

    async fn revoke_if_active(
        &self,
        oid: Uuid,
        type_: ClientAuthorizationType,
        now: DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ClientAuthorizationRepositoryError {
    #[error("failed to query client authorization")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A fully prepared authorization row, committed together with the device
/// request it belongs to.
///
/// Device tokens carry no browser session, so the preparing code owns the row
/// identifier (it is part of the signed token handle) and only the transaction
/// writes it.
#[derive(Debug, Clone)]
pub struct PreparedAuthorizationRecord {
    pub oid: Uuid,
    pub data: ClientAuthorizationData,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of redeeming an approved device request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceConsumeOutcome {
    /// The request was approved, consumed, and its token rows were stored.
    Consumed,
    /// The request is not in an approved, redeemable state.
    NotRedeemable,
    /// The user's authorization was revoked (or expired) before redemption.
    AuthorizationRevoked,
}

/// Device authorization persistence (RFC 8628).
///
/// Every state transition is a single conditional statement or a row-locked
/// transaction: concurrent polls, competing approvals and redemption races are
/// resolved by the database, never by in-process locks.
#[async_trait]
pub trait DeviceAuthorizationRepository: Send + Sync {
    /// Persists a new pending request. Fails when an active request already
    /// holds the same user code.
    async fn create_device_request(
        &self,
        client_oid: ClientOid,
        data: DeviceAuthorizationRequestData,
        expires_at: DateTime<Utc>,
    ) -> Result<ClientAuthorization, DeviceAuthorizationRepositoryError>;

    async fn find_device_request_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

    /// Finds the request holding the given device code digest.
    async fn find_device_request_by_device_code_digest(
        &self,
        digest: &str,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

    /// Finds the newest request that is still active (not consumed, not
    /// revoked) for the normalized user code.
    async fn find_active_device_request_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

    async fn find_device_authorization_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

    /// Atomically consumes the browser code and binds its winning login to the authenticated session.
    async fn claim_device_request(
        &self,
        request_oid: Uuid,
        login_oid: Uuid,
        session_oid: SessionOid,
        now: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError> {
        let _ = (request_oid, login_oid, session_oid, now);
        Err(DeviceAuthorizationRepositoryError::QueryFailed(Box::new(
            std::io::Error::other("device login claim not implemented"),
        )))
    }

    /// Records the polling schedule for a request.
    ///
    /// Locks the request row, so concurrent polls for one device code are
    /// serialized; a poll inside the effective interval only grows
    /// `slow_down_seconds`.
    async fn record_device_poll(
        &self,
        request_oid: Uuid,
        polled_at: DateTime<Utc>,
    ) -> Result<DevicePollOutcome, DeviceAuthorizationRepositoryError>;

    /// Approves a pending request and creates its authorization relation in
    /// one transaction. Returns the relation's oid.
    ///
    /// The relation itself never expires; it is withdrawn by revocation or by
    /// deleting the client. The request must still be pending, unrevoked and
    /// unexpired, and the approved scope must stay inside the requested scope.
    async fn approve_device_request(
        &self,
        request_oid: Uuid,
        approval: DeviceAuthorizationApproval,
        decided_at: DateTime<Utc>,
    ) -> Result<Option<Uuid>, DeviceAuthorizationRepositoryError>;

    /// Denies a pending request. Returns `false` when the request is no longer
    /// pending (already decided, consumed, expired or revoked).
    async fn deny_device_request(
        &self,
        request_oid: Uuid,
        user_oid: Uuid,
        decided_at: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError>;

    /// Consumes an approved request and stores its token rows in one
    /// transaction.
    ///
    /// Nothing is written when the request is not redeemable or the relation
    /// was revoked meanwhile, so a failed issuance can be retried by polling
    /// again.
    async fn consume_device_request_with_tokens(
        &self,
        request_oid: Uuid,
        records: Vec<PreparedAuthorizationRecord>,
        now: DateTime<Utc>,
    ) -> Result<DeviceConsumeOutcome, DeviceAuthorizationRepositoryError>;

    /// Revokes a device authorization relation.
    async fn revoke_device_authorization(
        &self,
        device_authorization_oid: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, DeviceAuthorizationRepositoryError>;

    /// Revokes every relation a user holds, used by account-level logout.
    async fn revoke_device_authorizations_for_user(
        &self,
        user_oid: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, DeviceAuthorizationRepositoryError>;

    /// Deletes expired device requests. Relations are never deleted here.
    async fn delete_expired_device_requests(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, DeviceAuthorizationRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthorizationRepositoryError {
    #[error("failed to query device authorization")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("user code is already in use by an active device request")]
    UserCodeConflict,
    #[error("approved scope is not covered by the requested scope")]
    ScopeNotGrantable,
}
