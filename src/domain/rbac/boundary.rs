//! Business RBAC scope boundaries.
//!
//! A business permission may reference an OAuth scope that is issued to an
//! external API resource. That reference must never point at instance
//! management capabilities, standard OIDC identity scopes or existing
//! account/session self-service scopes.

use crate::authorization::catalog::is_reserved_management_name;
use crate::openid_connect::model::claim::StandardScopes;

pub const STANDARD_OIDC_SCOPES: &[&str] = &[
    StandardScopes::OPENID,
    StandardScopes::PROFILE,
    StandardScopes::EMAIL,
    StandardScopes::ADDRESS,
    StandardScopes::PHONE,
    StandardScopes::OFFLINE_ACCESS,
];

pub const ACCOUNT_SELF_SERVICE_SCOPES: &[&str] = &[
    "account.*",
    "account.read",
    "account.update",
    "session.*",
    "session.read",
    "session.revoke",
    "password.change",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BusinessScopeBoundaryError {
    #[error("management scopes are reserved and cannot be used as business permissions")]
    ManagementScopeReserved,
    #[error("standard OIDC scope cannot be used as a business permission: {0}")]
    StandardOidcScope(String),
    #[error("account/session self-service scope cannot be used as a business permission: {0}")]
    SelfServiceScope(String),
    #[error("invalid OAuth scope token for a business permission")]
    InvalidScopeToken,
}

/// Pure boundary rule used by permission creation, update, seeds and
/// repository reference checks. Exact names only; no prefix resolution.
pub fn validate_business_scope_reference(scope: &str) -> Result<(), BusinessScopeBoundaryError> {
    if !valid_scope_token(scope) {
        // Report reserved-prefix misuse separately so diagnostics do not hide
        // an attempted management grant behind a generic syntax error.
        if is_reserved_management_name(scope) {
            return Err(BusinessScopeBoundaryError::ManagementScopeReserved);
        }
        return Err(BusinessScopeBoundaryError::InvalidScopeToken);
    }
    if is_reserved_management_name(scope) {
        return Err(BusinessScopeBoundaryError::ManagementScopeReserved);
    }
    if STANDARD_OIDC_SCOPES.contains(&scope) {
        return Err(BusinessScopeBoundaryError::StandardOidcScope(
            scope.to_owned(),
        ));
    }
    if ACCOUNT_SELF_SERVICE_SCOPES.contains(&scope) {
        return Err(BusinessScopeBoundaryError::SelfServiceScope(
            scope.to_owned(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 255
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

#[cfg(test)]
mod tests {
    use super::{BusinessScopeBoundaryError, validate_business_scope_reference};

    #[test]
    fn management_names_are_rejected_even_unknown_ones() {
        for scope in ["management.user.read", "management.unknown"] {
            assert_eq!(
                validate_business_scope_reference(scope),
                Err(BusinessScopeBoundaryError::ManagementScopeReserved),
                "{scope}"
            );
        }
    }

    #[test]
    fn standard_and_self_service_scopes_are_rejected() {
        for scope in [
            "openid",
            "profile",
            "email",
            "offline_access",
            "phone",
            "address",
        ] {
            assert!(matches!(
                validate_business_scope_reference(scope),
                Err(BusinessScopeBoundaryError::StandardOidcScope(_))
            ));
        }
        for scope in [
            "account.*",
            "account.read",
            "account.update",
            "session.*",
            "session.read",
            "session.revoke",
            "password.change",
        ] {
            assert!(matches!(
                validate_business_scope_reference(scope),
                Err(BusinessScopeBoundaryError::SelfServiceScope(_))
            ));
        }
    }

    #[test]
    fn business_scopes_keep_exact_identifiers() {
        for scope in ["commerce.orders.read", "support.orders.read", "orders"] {
            assert_eq!(validate_business_scope_reference(scope), Ok(()), "{scope}");
        }
        assert_eq!(
            validate_business_scope_reference("orders read"),
            Err(BusinessScopeBoundaryError::InvalidScopeToken)
        );
        assert_eq!(
            validate_business_scope_reference("订单"),
            Err(BusinessScopeBoundaryError::InvalidScopeToken)
        );
    }
}
