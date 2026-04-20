use super::claim::StandardScopes;
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet {
    pub openid: bool,
    pub profile: bool,
    pub email: bool,
    pub offline_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeParseError {
    scope_name: String,
}

impl ScopeParseError {
    pub fn scope_name(&self) -> &str {
        &self.scope_name
    }
}

impl fmt::Display for ScopeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown scope: {}", self.scope_name)
    }
}

impl std::error::Error for ScopeParseError {}

impl ScopeSet {
    pub fn parse(scope_str: &str) -> Result<Self, ScopeParseError> {
        let mut set = Self::default();

        for scope in scope_str.split_whitespace() {
            match scope {
                StandardScopes::OPENID => set.openid = true,
                StandardScopes::PROFILE => set.profile = true,
                StandardScopes::EMAIL => set.email = true,
                StandardScopes::OFFLINE_ACCESS => set.offline_access = true,
                other => {
                    return Err(ScopeParseError {
                        scope_name: other.to_owned(),
                    });
                }
            }
        }

        Ok(set)
    }

    pub fn to_scope_string(&self) -> String {
        let mut scopes = Vec::new();
        if self.openid {
            scopes.push(StandardScopes::OPENID);
        }
        if self.profile {
            scopes.push(StandardScopes::PROFILE);
        }
        if self.email {
            scopes.push(StandardScopes::EMAIL);
        }
        if self.offline_access {
            scopes.push(StandardScopes::OFFLINE_ACCESS);
        }
        scopes.join(" ")
    }

    pub fn contains_openid(&self) -> bool {
        self.openid
    }
}

impl FromStr for ScopeSet {
    type Err = ScopeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::ScopeSet;

    #[test]
    fn parse_valid_scope_string() {
        let scope = ScopeSet::parse("openid profile email").unwrap();
        assert!(scope.openid);
        assert!(scope.profile);
        assert!(scope.email);
        assert!(!scope.offline_access);
    }

    #[test]
    fn parse_scope_with_offline_access() {
        let scope = ScopeSet::parse("openid offline_access").unwrap();
        assert!(scope.openid);
        assert!(scope.offline_access);
        assert!(!scope.profile);
        assert!(!scope.email);
    }

    #[test]
    fn reject_unknown_scope() {
        let err = ScopeSet::parse("openid custom_scope").unwrap_err();
        assert_eq!(err.scope_name(), "custom_scope");
    }

    #[test]
    fn parse_empty_scope_string() {
        let scope = ScopeSet::parse("").unwrap();
        assert!(!scope.openid);
        assert!(!scope.profile);
        assert!(!scope.email);
        assert!(!scope.offline_access);
    }

    #[test]
    fn to_scope_string() {
        let scope = ScopeSet {
            openid: true,
            profile: true,
            email: false,
            offline_access: true,
        };
        assert_eq!(scope.to_scope_string(), "openid profile offline_access");
    }

    #[test]
    fn contains_openid() {
        let scope = ScopeSet::parse("openid").unwrap();
        assert!(scope.contains_openid());

        let scope_no_openid = ScopeSet::parse("profile").unwrap();
        assert!(!scope_no_openid.contains_openid());
    }
}
