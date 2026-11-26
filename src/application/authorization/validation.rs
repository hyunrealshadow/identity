use crate::error::AppError;

/// Shared maximum length in Unicode scalar values for mutation audit reasons.
pub const MAX_REASON_LENGTH: usize = 1_000;

/// Shared maximum length in Unicode scalar values for idempotency client mutation IDs.
pub const MAX_CLIENT_MUTATION_ID_LENGTH: usize = 255;

/// Trim an audit reason and validate its maximum character length, delegating error
/// construction to the calling application module.
pub fn validate_reason_with<F>(reason: &str, too_long: F) -> Result<String, AppError>
where
    F: FnOnce(usize) -> AppError,
{
    let trimmed = reason.trim();
    if trimmed.chars().count() > MAX_REASON_LENGTH {
        return Err(too_long(MAX_REASON_LENGTH));
    }
    Ok(trimmed.to_owned())
}

/// Validate an optional client mutation identifier's maximum character length, delegating error
/// construction to the calling application module.
pub fn validate_client_mutation_id_with<F>(value: Option<&str>, too_long: F) -> Result<(), AppError>
where
    F: FnOnce(usize) -> AppError,
{
    if value.is_some_and(|v| v.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH) {
        return Err(too_long(MAX_CLIENT_MUTATION_ID_LENGTH));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, io};

    use super::*;

    #[test]
    fn validates_and_trims_reason_within_limit() {
        let valid = "a".repeat(MAX_REASON_LENGTH);
        assert_eq!(
            validate_reason_with(&format!("  {valid}  "), |_| AppError::internal(
                io::Error::other("too long")
            ))
            .expect("trimmed value at max length should pass"),
            valid
        );

        let too_long = "a".repeat(MAX_REASON_LENGTH + 1);
        let err = validate_reason_with(&too_long, |max| {
            AppError::internal(io::Error::other(format!("max:{max}")))
        })
        .expect_err("value exceeding max length should fail");
        assert!(
            err.source()
                .is_some_and(|source| source.to_string().contains("max:1000"))
        );
    }

    #[test]
    fn validates_client_mutation_id_within_limit() {
        assert!(
            validate_client_mutation_id_with(None, |_| AppError::internal(io::Error::other(
                "unused"
            )))
            .is_ok()
        );

        let exact = "b".repeat(MAX_CLIENT_MUTATION_ID_LENGTH);
        assert!(
            validate_client_mutation_id_with(Some(&exact), |_| AppError::internal(
                io::Error::other("unused")
            ))
            .is_ok()
        );

        let too_long = "b".repeat(MAX_CLIENT_MUTATION_ID_LENGTH + 1);
        let err = validate_client_mutation_id_with(Some(&too_long), |max| {
            AppError::internal(io::Error::other(format!("max:{max}")))
        })
        .expect_err("mutation ID exceeding max length should fail");
        assert!(
            err.source()
                .is_some_and(|source| source.to_string().contains("max:255"))
        );
    }
}
