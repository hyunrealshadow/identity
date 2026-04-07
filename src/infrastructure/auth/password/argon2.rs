//! Argon2 password hashing and verification adapter.
//!
//! This is an internal module; external code uses [`super::PasswordHasherImpl`]
//! through the application-layer [`PasswordHasher`] trait.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher as _, SaltString},
};
use password_hash::rand_core::OsRng;

use crate::domain::{
    auth::password::{HashOptions, PasswordHashError, VerifyResult},
    user::model::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password},
};

pub(super) fn extract_opts(options: &HashOptions) -> Result<&Argon2Options, PasswordHashError> {
    match options {
        HashOptions::Argon2(opts) => Ok(opts),
    }
}

fn map_variant(v: Argon2Variant) -> Algorithm {
    match v {
        Argon2Variant::Argon2i => Algorithm::Argon2i,
        Argon2Variant::Argon2id => Algorithm::Argon2id,
    }
}

fn map_version(v: Argon2Version) -> Version {
    match v {
        Argon2Version::Argon2010 => Version::V0x10,
        Argon2Version::Argon2013 => Version::V0x13,
    }
}

fn build_argon2(opts: &Argon2Options) -> Result<Argon2<'static>, PasswordHashError> {
    let params = Params::new(opts.memory_cost, opts.time_cost, opts.parallelism, None)
        .map_err(|e| PasswordHashError::HashFailed(e.to_string()))?;
    Ok(Argon2::new(
        map_variant(opts.variant.clone()),
        map_version(opts.version.clone()),
        params,
    ))
}

pub(super) fn hash(password: &str, opts: &Argon2Options) -> Result<Password, PasswordHashError> {
    let argon2 = build_argon2(opts)?;
    let salt = SaltString::generate(&mut OsRng);
    let hashed = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordHashError::HashFailed(e.to_string()))?;
    let hash = hashed
        .hash
        .ok_or_else(|| PasswordHashError::HashFailed("missing hash output".to_owned()))?
        .to_string();

    Ok(Password::Argon2(Argon2Password {
        hash,
        salt: salt.to_string(),
        options: opts.clone(),
    }))
}

pub(super) fn verify(
    password: &str,
    stored: &Argon2Password,
    current_opts: &Argon2Options,
) -> Result<VerifyResult, PasswordHashError> {
    let salt = SaltString::from_b64(&stored.salt)
        .map_err(|e| PasswordHashError::InvalidStoredHash(e.to_string()))?;

    let argon2 = build_argon2(&stored.options)?;
    let actual_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordHashError::HashFailed(e.to_string()))?
        .hash
        .ok_or_else(|| PasswordHashError::HashFailed("missing hash output".to_owned()))?
        .to_string();

    if actual_hash != stored.hash {
        return Ok(VerifyResult::Failure);
    }

    if &stored.options == current_opts {
        Ok(VerifyResult::Success)
    } else {
        Ok(VerifyResult::NeedsRehash)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_argon2, hash, verify};
    use crate::domain::{
        auth::password::VerifyResult,
        user::model::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password},
    };

    fn opts() -> Argon2Options {
        Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 1,
            memory_cost: 8,
            parallelism: 1,
        }
    }

    #[test]
    fn build_argon2_rejects_invalid_params() {
        let options = Argon2Options {
            memory_cost: 0,
            ..opts()
        };

        let error = build_argon2(&options).unwrap_err();

        assert!(matches!(
            error,
            crate::domain::auth::password::PasswordHashError::HashFailed(_)
        ));
    }

    #[test]
    fn hash_returns_password_with_original_options() {
        let options = opts();
        let password = hash("secret", &options).unwrap();

        let Password::Argon2(stored) = password;
        assert!(!stored.hash.is_empty());
        assert!(!stored.salt.is_empty());
        assert_eq!(stored.options, options);
    }

    #[test]
    fn verify_rejects_invalid_base64_salt() {
        let stored = Argon2Password {
            hash: "hash".to_owned(),
            salt: "*** not base64 ***".to_owned(),
            options: opts(),
        };

        let error = verify("secret", &stored, &opts()).unwrap_err();

        assert!(matches!(
            error,
            crate::domain::auth::password::PasswordHashError::InvalidStoredHash(_)
        ));
    }

    #[test]
    fn verify_returns_failure_when_hash_does_not_match() {
        let Password::Argon2(mut stored) = hash("secret", &opts()).unwrap();
        stored.hash.push('x');

        let result = verify("secret", &stored, &opts()).unwrap();

        assert_eq!(result, VerifyResult::Failure);
    }
}
