mod authorization;
mod context;
mod error;
mod modules;

use async_graphql::{EmptySubscription, Schema};

pub use context::RequestContext;
use modules::{MutationRoot, QueryRoot};

pub type ApiSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub const RESOURCE_AUDIENCE: &str = "urn:identity:graphql";

pub fn build_schema(max_depth: usize, max_complexity: usize) -> ApiSchema {
    Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        EmptySubscription,
    )
    .limit_depth(max_depth)
    .limit_complexity(max_complexity)
    .finish()
}

#[cfg(test)]
mod tests {
    use super::build_schema;

    #[test]
    fn schema_exposes_mfa_self_service_contract() {
        let sdl = build_schema(20, 1_000).sdl();

        for field in [
            "security: AccountSecurity!",
            "beginTotpEnrollment(",
            "confirmTotpEnrollment(",
            "changeTotpEnrollmentAlgorithm(",
            "enum TotpAlgorithm",
            "SHA1",
            "SHA256",
            "SHA512",
            "disableTotp(",
            "regenerateRecoveryCodes(",
            "recoveryCodesRemaining: Int!",
        ] {
            assert!(sdl.contains(field), "schema is missing {field}");
        }
    }

    #[test]
    fn schema_exposes_separate_identifier_updates_without_phone_management() {
        let sdl = build_schema(20, 1_000).sdl();

        assert!(sdl.contains("updateUsername("));
        assert!(sdl.contains("input UpdateUsernameInput"));
        assert!(sdl.contains("updateEmail("));
        assert!(sdl.contains("input UpdateEmailInput"));
        assert!(!sdl.contains("updateAccountIdentifiers("));
        assert!(!sdl.contains("phoneNumber"));
    }
}
