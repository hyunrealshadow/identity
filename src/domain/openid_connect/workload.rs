use std::error::Error as StdError;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::client::model::ClientOid;

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
    pub client_oid: ClientOid,
    pub client_secret: String,
    pub generation: i64,
    pub secret_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginRotationPolicy {
    pub credential_lifetime: Duration,
    pub rotate_before_expiry: Duration,
    pub retire_after: Duration,
}

pub const BUILTIN_CLIENT_SECRET_LIFETIME: Duration = Duration::days(90);

impl Default for LoginRotationPolicy {
    fn default() -> Self {
        Self {
            credential_lifetime: BUILTIN_CLIENT_SECRET_LIFETIME,
            rotate_before_expiry: Duration::days(30),
            retire_after: Duration::hours(24),
        }
    }
}

#[derive(Debug, Error)]
pub enum LoginRuntimeRepositoryError {
    #[error("failed to query login runtime state")]
    QueryFailed(#[source] Box<dyn StdError + Send + Sync>),
}

#[async_trait::async_trait]
pub trait LoginRuntimeRepository: Send + Sync {
    /// Returns the runtime configuration for the built-in Login workload, or
    /// `None` when installation has not created one yet.
    async fn login_runtime_config(
        &self,
        client_oid: ClientOid,
        now: DateTime<Utc>,
    ) -> Result<Option<LoginRuntimeConfig>, LoginRuntimeRepositoryError>;

    /// Rotates existing secrets for every built-in OIDC client whose newest
    /// secret is due. Clients without a secret are skipped.
    async fn rotate_builtin_if_due(
        &self,
        now: DateTime<Utc>,
        policy: &LoginRotationPolicy,
    ) -> Result<u64, LoginRuntimeRepositoryError>;
}
