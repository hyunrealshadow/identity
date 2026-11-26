//! Input normalization, guards and repository error mapping for user management.

use super::*;

pub(super) fn reject_self_credential_action(
    authority: &UserManagementAuthority,
    target: UserOid,
) -> Result<(), AppError> {
    if matches!(
        authority.actor.principal,
        ActorPrincipal::User { user_oid, .. } if user_oid == target
    ) {
        return Err(user_management::error::SelfCredentialActionNotAllowed.into());
    }
    Ok(())
}

pub(super) fn page_conflict() -> AppError {
    user_management::error::PageArgumentsConflict.into()
}

pub(super) fn validate_page_size(value: u32, field: &'static str) -> Result<usize, AppError> {
    if !(1..=MAX_PAGE_SIZE).contains(&value) {
        return Err(user_management::error::PageSizeInvalid::new(MAX_PAGE_SIZE).with_field(field));
    }
    Ok(value as usize)
}

/// Normalize an optional audit annotation shared by every user management
/// mutation. Blank input becomes an empty reason; over-long supplied text is
/// rejected.
pub(super) fn validate_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.chars().count() > MAX_REASON_LENGTH {
        return Err(
            user_management::error::ValidationFailed::new().with_field_error(
                "reason",
                user_management::error::ReasonTooLong::new(MAX_REASON_LENGTH),
            ),
        );
    }
    Ok(reason.to_owned())
}

pub(super) fn validate_client_mutation_id(value: Option<&str>) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > MAX_CLIENT_MUTATION_ID_LENGTH {
        return Err(
            user_management::error::ValidationFailed::new().with_field_error(
                "client_mutation_id",
                user_management::error::InvalidClientMutationId::new(MAX_CLIENT_MUTATION_ID_LENGTH),
            ),
        );
    }
    Ok(())
}

pub(super) fn validate_username_field(value: &str) -> Result<(String, String), AppError> {
    match validate_username(value) {
        Ok(normalized) => Ok((value.trim().to_owned(), normalized)),
        Err(UsernameValidationError::Empty) => Err(user_management::error::ValidationFailed::new()
            .with_field_error("username", account::error::UsernameRequired)),
        Err(UsernameValidationError::InvalidLength | UsernameValidationError::InvalidCharacter) => {
            Err(user_management::error::ValidationFailed::new()
                .with_field_error("username", account::error::UsernameInvalid))
        }
    }
}

pub(super) fn validate_email_field(value: &str) -> Result<(String, String), AppError> {
    match normalize_email(value) {
        Ok(normalized) => Ok((value.trim().to_owned(), normalized)),
        Err(EmailNormalizationError::Empty) => Err(user_management::error::ValidationFailed::new()
            .with_field_error("email", account::error::EmailRequired)),
        Err(EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain) => {
            Err(user_management::error::ValidationFailed::new()
                .with_field_error("email", account::error::EmailInvalid))
        }
    }
}

pub(super) fn normalize_filter(filter: UserFilter) -> Result<NormalizedFilter, AppError> {
    let query = normalize_filter_text(filter.query, "query", MAX_QUERY_FILTER_LENGTH)?;
    let username = normalize_filter_text(filter.username, "username", MAX_USERNAME_FILTER_LENGTH)?;
    let email = normalize_filter_text(filter.email, "email", MAX_EMAIL_FILTER_LENGTH)?;
    if let (Some(from), Some(before)) = (filter.created_from, filter.created_before)
        && from >= before
    {
        return Err(
            user_management::error::InvalidDateRange::new("created_from")
                .with_field("created_from"),
        );
    }
    Ok(NormalizedFilter {
        query,
        username,
        email,
        enabled: filter.enabled,
        locked: filter.locked,
        created_from: filter.created_from,
        created_before: filter.created_before,
    })
}

pub(super) fn normalize_filter_text(
    value: Option<String>,
    field: &'static str,
    max: usize,
) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > max {
        return Err(user_management::error::InvalidFilter::new(field)
            .max(max)
            .with_field(field));
    }
    Ok(Some(value.to_lowercase()))
}

pub(super) fn map_mutation_outcome(
    outcome: UserManagementMutationOutcome,
) -> Result<UserManagementRecord, AppError> {
    match outcome {
        UserManagementMutationOutcome::Success(record) => Ok(*record),
        UserManagementMutationOutcome::UserNotFound => {
            Err(user_management::error::UserNotFound.into())
        }
        UserManagementMutationOutcome::VersionConflict { current_version } => Err(
            user_management::error::VersionConflict::new(current_version)
                .with_field("expected_version"),
        ),
        UserManagementMutationOutcome::LastOwnerProtected => {
            Err(AppError::from(OwnerProtectionError::LastOwnerProtected))
        }
        UserManagementMutationOutcome::UsernameExists => {
            Err(account::error::UsernameExists.with_field("username"))
        }
        UserManagementMutationOutcome::EmailExists => {
            Err(account::error::EmailExists.with_field("email"))
        }
        UserManagementMutationOutcome::NotDisabled => {
            Err(user_management::error::UserNotDisabled.into())
        }
        UserManagementMutationOutcome::NoPassword => {
            Err(user_management::error::UserHasNoPassword.into())
        }
        UserManagementMutationOutcome::SessionNotFound => {
            Err(user_management::error::SessionNotFound.into())
        }
    }
}

/// Characters of a generated temporary password: four unambiguous character
/// classes without look-alikes (`0`/`O` or `1`/`l`/`I`).
pub(super) const TEMPORARY_PASSWORD_LOWER: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
pub(super) const TEMPORARY_PASSWORD_UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
pub(super) const TEMPORARY_PASSWORD_DIGITS: &[u8] = b"23456789";
pub(super) const TEMPORARY_PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*";
pub(super) const TEMPORARY_PASSWORD_ALL: &[u8] =
    b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
pub(super) const TEMPORARY_PASSWORD_LENGTH: usize = 16;

/// Sixteen random characters covering lowercase, uppercase, digits, and symbols.
pub(super) fn temporary_password() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut pick = |alphabet: &[u8]| alphabet[rng.random_range(0..alphabet.len())];
    let mut chars = Vec::with_capacity(TEMPORARY_PASSWORD_LENGTH);
    chars.push(pick(TEMPORARY_PASSWORD_LOWER));
    chars.push(pick(TEMPORARY_PASSWORD_UPPER));
    chars.push(pick(TEMPORARY_PASSWORD_DIGITS));
    chars.push(pick(TEMPORARY_PASSWORD_SYMBOLS));
    while chars.len() < TEMPORARY_PASSWORD_LENGTH {
        chars.push(pick(TEMPORARY_PASSWORD_ALL));
    }
    for i in (1..chars.len()).rev() {
        let j = rng.random_range(0..=i);
        chars.swap(i, j);
    }
    chars.into_iter().map(char::from).collect()
}

pub(super) fn map_repository_error(error: UserManagementRepositoryError) -> AppError {
    match error {
        UserManagementRepositoryError::Storage(source) => user_management::error::StorageFailed
            .with_source(UserManagementRepositoryError::Storage(source)),
        UserManagementRepositoryError::Authorization(source) => AppError::from(source),
        UserManagementRepositoryError::AuditFailed(source) => {
            authorization::error::AuditWriteFailed
                .with_source(UserManagementRepositoryError::AuditFailed(source))
        }
        UserManagementRepositoryError::CorruptRecord => {
            user_management::error::StorageFailed.into()
        }
    }
}
