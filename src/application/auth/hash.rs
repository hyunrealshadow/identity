//! Password hashing port for authentication use cases.
//!
//! Concrete implementations live in the infrastructure crate.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::user::model::{Argon2Options, Password};

#[derive(Debug, Error)]
pub enum PasswordHashError {
    #[error("invalid hash options: {0}")]
    InvalidOptions(String),

    #[error("hashing failed: {0}")]
    HashFailed(String),

    #[error("invalid stored hash: {0}")]
    InvalidStoredHash(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    Success,
    Failure,
    NeedsRehash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashOptions {
    Argon2(Argon2Options),
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError>;

    fn verify(
        &self,
        password: &str,
        stored: &Password,
        options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError>;
}
