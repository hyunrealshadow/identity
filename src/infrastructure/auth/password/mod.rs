//! Infrastructure implementation of the password hashing contract.
//!
//! # Public surface
//!
//! [`PasswordHasherImpl`] is the single type you wire into your DI container
//! or application service. It implements the application-layer
//! [`PasswordHasher`] trait and dispatches to the correct algorithm
//! implementation based on the [`HashOptions`] variant supplied by the caller.
//!
//! Algorithm-specific modules are kept private to this crate;
//! callers never need to import them.

mod argon2;

use crate::domain::{
    auth::password::{HashOptions, PasswordHashError, PasswordHasher, VerifyResult},
    user::model::Password,
};

#[derive(Debug, Clone, Default)]
pub struct PasswordHasherImpl;

impl PasswordHasherImpl {
    pub fn new() -> Self {
        Self
    }
}

impl PasswordHasher for PasswordHasherImpl {
    fn hash(&self, password: &str, options: &HashOptions) -> Result<Password, PasswordHashError> {
        match options {
            HashOptions::Argon2(opts) => argon2::hash(password, opts),
        }
    }

    fn verify(
        &self,
        password: &str,
        stored: &Password,
        options: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        match stored {
            Password::Argon2(argon2_pw) => {
                let current_opts = argon2::extract_opts(options)?;
                argon2::verify(password, argon2_pw, current_opts)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        auth::password::{HashOptions, VerifyResult},
        user::model::{Argon2Options, Argon2Variant, Argon2Version},
    };

    fn opts() -> HashOptions {
        HashOptions::Argon2(Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 1,
            memory_cost: 8,
            parallelism: 1,
        })
    }

    fn argon2_opts(f: impl FnOnce(Argon2Options) -> Argon2Options) -> HashOptions {
        let HashOptions::Argon2(base) = opts();
        HashOptions::Argon2(f(base))
    }

    #[test]
    fn hash_and_verify_success() {
        let h = PasswordHasherImpl::new();
        let stored = h.hash("correct-horse-battery-staple", &opts()).unwrap();
        let result = h
            .verify("correct-horse-battery-staple", &stored, &opts())
            .unwrap();
        assert_eq!(result, VerifyResult::Success);
    }

    #[test]
    fn wrong_password_returns_failure() {
        let h = PasswordHasherImpl::new();
        let stored = h.hash("correct-horse-battery-staple", &opts()).unwrap();
        let result = h.verify("hunter2", &stored, &opts()).unwrap();
        assert_eq!(result, VerifyResult::Failure);
    }

    #[test]
    fn changed_time_cost_needs_rehash() {
        let h = PasswordHasherImpl::new();
        let stored = h.hash("my-password", &opts()).unwrap();
        let new_opts = argon2_opts(|o| Argon2Options { time_cost: 2, ..o });
        assert_eq!(
            h.verify("my-password", &stored, &new_opts).unwrap(),
            VerifyResult::NeedsRehash,
        );
    }

    #[test]
    fn changed_variant_needs_rehash() {
        let h = PasswordHasherImpl::new();
        let stored = h.hash("my-password", &opts()).unwrap();
        let new_opts = argon2_opts(|o| Argon2Options {
            variant: Argon2Variant::Argon2i,
            ..o
        });
        assert_eq!(
            h.verify("my-password", &stored, &new_opts).unwrap(),
            VerifyResult::NeedsRehash,
        );
    }
}
