//! Published field requirements. Client preflight is advisory; live authority,
//! target ownership and transactional authorization remain server decisions.
use async_graphql::{Enum, InputObject, TypeDirective};
use identity_application::authorization::DEFAULT_RECENT_AAL2_TTL;
use identity_domain::{
    auth::{ELEVATED_AUTHENTICATION_TTL, RECENT_AUTHENTICATION_TTL},
    authorization::{HumanAuthenticationRequirement, ManagementScope},
    openid_connect::ApiScope,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enum)]
pub(crate) enum AccessAuthentication {
    Session,
    #[graphql(name = "AAL2")]
    Aal2,
    Recent,
    #[graphql(name = "RECENT_AAL2")]
    RecentAal2,
    /// Assurance depends on the account's registered factors.
    AccountSecurity,
}

#[derive(Clone, Debug, InputObject)]
pub(crate) struct AccessPolicy {
    pub scopes: Vec<String>,
    pub authentication: AccessAuthentication,
    pub max_age: Option<i32>,
    pub elevated_max_age: Option<i32>,
    pub user_only: bool,
    /// Additional target-dependent authorization cannot be proved from tokens.
    pub runtime: bool,
}

impl AccessPolicy {
    pub(crate) fn authenticated() -> Self {
        Self {
            scopes: Vec::new(),
            authentication: AccessAuthentication::Session,
            max_age: None,
            elevated_max_age: None,
            user_only: false,
            runtime: false,
        }
    }

    pub(crate) fn dynamic() -> Self {
        Self {
            runtime: true,
            ..Self::authenticated()
        }
    }

    pub(crate) fn scope(scope: ApiScope) -> Self {
        Self {
            scopes: vec![scope.name().to_owned()],
            user_only: true,
            ..Self::authenticated()
        }
    }

    pub(crate) fn management(scope: ManagementScope) -> Self {
        let definition = scope.definition();
        let (authentication, max_age) = match definition.human_authentication {
            HumanAuthenticationRequirement::None => (AccessAuthentication::Session, None),
            HumanAuthenticationRequirement::Aal2 => (AccessAuthentication::Aal2, None),
            HumanAuthenticationRequirement::RecentAal2 => (
                AccessAuthentication::RecentAal2,
                Some(DEFAULT_RECENT_AAL2_TTL.as_secs() as i32),
            ),
        };
        Self {
            scopes: vec![scope.name().to_owned()],
            authentication,
            max_age,
            user_only: !definition.flows.confidential_client_credentials,
            runtime: true,
            ..Self::authenticated()
        }
    }

    pub(crate) fn recent(aal2: bool) -> Self {
        Self {
            authentication: if aal2 {
                AccessAuthentication::RecentAal2
            } else {
                AccessAuthentication::Recent
            },
            max_age: Some(
                if aal2 {
                    ELEVATED_AUTHENTICATION_TTL
                } else {
                    RECENT_AUTHENTICATION_TTL
                }
                .as_secs() as i32,
            ),
            user_only: true,
            ..Self::authenticated()
        }
    }

    pub(crate) fn account_security() -> Self {
        Self {
            authentication: AccessAuthentication::AccountSecurity,
            max_age: Some(RECENT_AUTHENTICATION_TTL.as_secs() as i32),
            elevated_max_age: Some(ELEVATED_AUTHENTICATION_TTL.as_secs() as i32),
            user_only: true,
            runtime: true,
            ..Self::authenticated()
        }
    }
}

/// Requirements are conjunctive, including repeated declarations on a field.
/// An empty scope list adds no permission requirement beyond the authenticated
/// transport. Runtime requirements are not a grant or a client-side guarantee.
#[TypeDirective(location = "FieldDefinition", repeatable)]
pub(crate) fn access(policy: AccessPolicy) {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::graphql;
    use async_graphql::parser::{
        parse_schema,
        types::{TypeKind, TypeSystemDefinition},
    };

    #[test]
    fn every_root_field_publishes_access_requirements() {
        let document = parse_schema(graphql::schema_sdl()).unwrap();
        let roots: BTreeSet<_> = document
            .definitions
            .iter()
            .filter_map(|definition| {
                let TypeSystemDefinition::Schema(schema) = definition else {
                    return None;
                };
                Some([
                    schema.node.query.as_ref(),
                    schema.node.mutation.as_ref(),
                    schema.node.subscription.as_ref(),
                ])
            })
            .flatten()
            .flatten()
            .map(|name| name.node.to_string())
            .collect();
        assert!(
            !roots.is_empty(),
            "the executable schema must declare its operation roots"
        );
        let mut visited = BTreeSet::new();
        for definition in document.definitions {
            let TypeSystemDefinition::Type(definition) = definition else {
                continue;
            };
            if !roots.contains(definition.node.name.node.as_str()) {
                continue;
            }
            visited.insert(definition.node.name.node.to_string());
            let TypeKind::Object(object) = definition.node.kind else {
                panic!("root must be an object")
            };
            for field in object.fields {
                assert!(
                    field
                        .node
                        .directives
                        .iter()
                        .any(|d| d.node.name.node == "access"),
                    "{}.{} has no access directive",
                    definition.node.name.node,
                    field.node.name.node
                );
            }
        }
        assert_eq!(visited, roots, "every declared root must be checked");
    }

    #[test]
    fn management_metadata_uses_the_live_catalog_and_time_window() {
        for scope in ManagementScope::ALL {
            let policy = AccessPolicy::management(scope);
            assert_eq!(policy.scopes, vec![scope.name()]);
            assert_eq!(
                policy.user_only,
                !scope.definition().flows.confidential_client_credentials
            );
            match scope.definition().human_authentication {
                HumanAuthenticationRequirement::None => {
                    assert_eq!(policy.authentication, AccessAuthentication::Session)
                }
                HumanAuthenticationRequirement::Aal2 => {
                    assert_eq!(policy.authentication, AccessAuthentication::Aal2)
                }
                HumanAuthenticationRequirement::RecentAal2 => {
                    assert_eq!(policy.authentication, AccessAuthentication::RecentAal2);
                    assert_eq!(
                        policy.max_age,
                        Some(DEFAULT_RECENT_AAL2_TTL.as_secs() as i32)
                    );
                }
            }
        }
    }

    #[test]
    fn nested_protected_fields_keep_their_requirements() {
        let document = parse_schema(graphql::schema_sdl()).unwrap();
        for (type_name, fields) in [
            (
                "User",
                &[
                    "version",
                    "enabled",
                    "locked",
                    "lockedUntil",
                    "failedAttempts",
                    "groups",
                    "roleBindings",
                    "effectivePermissions",
                ][..],
            ),
            (
                "InstanceOverview",
                &["users", "applications", "sessions", "resources"][..],
            ),
        ] {
            let object = document
                .definitions
                .iter()
                .find_map(|d| {
                    let TypeSystemDefinition::Type(d) = d else {
                        return None;
                    };
                    if d.node.name.node != type_name {
                        return None;
                    }
                    let TypeKind::Object(object) = &d.node.kind else {
                        return None;
                    };
                    Some(object)
                })
                .unwrap();
            for name in fields {
                let field = object
                    .fields
                    .iter()
                    .find(|f| f.node.name.node == *name)
                    .unwrap();
                assert!(
                    field
                        .node
                        .directives
                        .iter()
                        .any(|d| d.node.name.node == "access"),
                    "{type_name}.{name}"
                );
            }
        }
    }
}
