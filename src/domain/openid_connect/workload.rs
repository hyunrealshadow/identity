use chrono::{DateTime, Utc};
use thiserror::Error;

/// Workloads that Identity recognizes on its internal management API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInWorkload {
    Login,
}

/// An authenticated internal API caller. The domain and application layers
/// only ever see this value; they never observe how the workload proved its
/// identity (static token, Kubernetes ServiceAccount JWT, mTLS, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedWorkload(pub BuiltInWorkload);

#[async_trait::async_trait]
pub trait WorkloadAuthenticator: Send + Sync {
    /// Authenticates a bearer credential and returns the workload it belongs
    /// to, or `None` when the credential is unknown or invalid.
    async fn authenticate(&self, token: &str) -> Option<AuthenticatedWorkload>;
}

/// The current Login runtime configuration: the OAuth client credential
/// generation that is active right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRuntimeConfig {
    pub client_oid: crate::client::model::ClientOid,
    pub client_secret: String,
    pub generation: i64,
    pub secret_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginRotationPolicy {
    pub credential_lifetime: chrono::Duration,
    pub rotate_before_expiry: chrono::Duration,
    pub retire_after: chrono::Duration,
}

#[derive(Debug, Error)]
pub enum LoginRuntimeRepositoryError {
    #[error("failed to query login runtime state")]
    QueryFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[async_trait::async_trait]
pub trait LoginRuntimeRepository: Send + Sync {
    /// Returns the runtime configuration for the built-in Login workload, or
    /// `None` when installation has not created one yet.
    async fn login_runtime_config(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Option<LoginRuntimeConfig>, LoginRuntimeRepositoryError>;

    /// Rotates the Login OAuth secret in a single transaction when the
    /// current secret has less remaining lifetime than
    /// `policy.rotate_before_expiry`. Returns the number of rotations
    /// performed.
    async fn rotate_if_due(
        &self,
        now: DateTime<Utc>,
        policy: &LoginRotationPolicy,
    ) -> Result<u64, LoginRuntimeRepositoryError>;
}
