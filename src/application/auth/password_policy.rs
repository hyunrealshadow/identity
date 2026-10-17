//! Rules for newly chosen passwords. Existing passwords remain usable.
use crate::error::{
    AppError,
    codes::{auth::AuthErrorCode, common::CommonErrorCode},
};
use async_trait::async_trait;

pub const MIN_PASSWORD_CHARACTERS: usize = 12;
pub const MAX_PASSWORD_CHARACTERS: usize = 1024;

#[async_trait]
pub trait BreachedPasswordChecker: Send + Sync {
    /// Never log the password or its hash. Dependency failures must fail closed.
    async fn is_breached(&self, password: &str) -> Result<bool, AppError>;
}

/// Used by composition roots which have not configured a breach checker.
pub struct UnavailableBreachChecker;
#[async_trait]
impl BreachedPasswordChecker for UnavailableBreachChecker {
    async fn is_breached(&self, _: &str) -> Result<bool, AppError> {
        Err(AppError::from_code(AuthErrorCode::PasswordCheckUnavailable))
    }
}

pub fn password_error(code: AuthErrorCode, field: &str) -> AppError {
    AppError::from_code(CommonErrorCode::ValidationFailed)
        .with_field_error(field, AppError::from_code(code))
}

pub fn validate_password(
    password: &str,
    identifiers: &[&str],
    field: &str,
) -> Result<(), AppError> {
    let length = password.chars().count();
    if length < MIN_PASSWORD_CHARACTERS {
        return Err(password_error(AuthErrorCode::PasswordTooShort, field));
    }
    if length > MAX_PASSWORD_CHARACTERS {
        return Err(password_error(AuthErrorCode::PasswordTooLong, field));
    }
    let folded = password.to_lowercase();
    let chars: Vec<char> = folded.chars().collect();
    let repeated = (1..=chars.len().min(4)).any(|period| {
        chars
            .iter()
            .enumerate()
            .all(|(i, c)| *c == chars[i % period])
    });
    let sequential = [
        "01234567890123456789",
        "12345678901234567890",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
    ]
    .iter()
    .any(|sequence| sequence.contains(&folded));
    if repeated
        || sequential
        || ["password", "qwerty", "letmein", "changeme"]
            .iter()
            .any(|weak| folded.trim_matches(|c: char| !c.is_alphabetic()) == *weak)
    {
        return Err(password_error(AuthErrorCode::PasswordTooWeak, field));
    }
    for identifier in identifiers {
        let identifier = identifier.to_lowercase();
        let local = identifier.split('@').next().unwrap_or_default();
        for candidate in [identifier.as_str(), local] {
            if candidate.chars().count() >= 3
                && (folded.contains(candidate) || edit_distance(&folded, candidate) <= 2)
            {
                return Err(password_error(AuthErrorCode::PasswordTooSimilar, field));
            }
        }
    }
    Ok(())
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    // Long identifiers cannot be within two edits of an accepted password.
    let left: Vec<char> = left.chars().collect();
    if left.len().abs_diff(right.len()) > 2 {
        return 3;
    }
    let mut row: Vec<usize> = (0..=right.len()).collect();
    for (i, a) in left.iter().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, b) in right.iter().enumerate() {
            let old = row[j + 1];
            row[j + 1] = (row[j] + 1)
                .min(old + 1)
                .min(diagonal + usize::from(a != b));
            diagonal = old;
        }
    }
    row[right.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    fn validate(password: &str, identifiers: &[&str]) -> Result<(), AppError> {
        validate_password(password, identifiers, "newPassword")
    }

    #[test]
    fn counts_unicode_and_preserves_password_text() {
        assert!(validate("安全密码", &[]).is_err());
        assert!(validate("春夏秋冬天地玄黄宇宙洪荒", &[]).is_ok());
        assert!(validate(" a varied pass phrase ", &[]).is_ok());
        assert!(validate(&"界".repeat(1025), &[]).is_err());
    }
    #[test]
    fn rejects_guessable_and_identifier_derived_passwords() {
        for password in [
            "aaaaaaaaaaaa",
            "abcdabcdabcd",
            "123456789012",
            "Password123456!",
        ] {
            assert!(validate(password, &[]).is_err(), "{password}");
        }
        assert!(validate("Alice-wonderland-903!", &["alice@example.test"]).is_err());
        assert!(validate("longusername12", &["longusername13"]).is_err());
        assert!(validate("a varied pass phrase", &["alice@example.test"]).is_ok());
    }
}
