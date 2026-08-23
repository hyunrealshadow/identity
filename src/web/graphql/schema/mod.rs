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
    use super::{
        build_schema,
        modules::account::{
            UpdateEmailInput, UpdateUsernameInput, validate_email, validate_username,
        },
    };

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

    #[test]
    fn username_validation_returns_a_username_field_error() {
        let error = validate_username(&UpdateUsernameInput {
            username: "@".to_owned(),
            client_mutation_id: None,
        })
        .unwrap_err();
        let fields = error.validation().unwrap().fields();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field(), "username");
        assert_eq!(fields[0].code(), 15_002);
    }

    #[test]
    fn email_validation_returns_an_email_field_error() {
        let error = validate_email(&UpdateEmailInput {
            email: "invalid".to_owned(),
            client_mutation_id: None,
        })
        .unwrap_err();
        let fields = error.validation().unwrap().fields();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field(), "email");
        assert_eq!(fields[0].code(), 15_004);
    }

    #[test]
    fn identifier_validation_normalizes_unique_keys_but_preserves_display_values() {
        let username_patch = validate_username(&UpdateUsernameInput {
            username: " Alice-01 ".to_owned(),
            client_mutation_id: None,
        })
        .unwrap();
        let email_patch = validate_email(&UpdateEmailInput {
            email: "USER@例子.测试".to_owned(),
            client_mutation_id: None,
        })
        .unwrap();

        assert_eq!(
            username_patch,
            identity_infrastructure::database::repository::user::UserIdentifierUpdate::Username {
                value: "Alice-01".to_owned(),
                normalized: "alice-01".to_owned(),
            }
        );
        assert_eq!(
            email_patch,
            identity_infrastructure::database::repository::user::UserIdentifierUpdate::Email {
                value: "USER@例子.测试".to_owned(),
                normalized: "user@xn--fsqu00a.xn--0zwm56d".to_owned(),
            }
        );
    }
}
