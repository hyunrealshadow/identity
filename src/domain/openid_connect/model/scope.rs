use super::claim::StandardScopes;
use std::{collections::BTreeSet, fmt, str::FromStr};

pub const API_RESOURCE: &str = "urn:identity:graphql";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiScope {
    Account,
    AccountUpdate,
    AccountRead,
    Session,
    SessionRevoke,
    SessionRead,
    PasswordChange,
}

impl ApiScope {
    pub const ACCOUNT: &'static str = "account";
    pub const ACCOUNT_UPDATE: &'static str = "account.update";
    pub const ACCOUNT_READ: &'static str = "account.read";
    pub const SESSION: &'static str = "session";
    pub const SESSION_REVOKE: &'static str = "session.revoke";
    pub const SESSION_READ: &'static str = "session.read";
    pub const PASSWORD_CHANGE: &'static str = "password.change";

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Account => Self::ACCOUNT,
            Self::AccountUpdate => Self::ACCOUNT_UPDATE,
            Self::AccountRead => Self::ACCOUNT_READ,
            Self::Session => Self::SESSION,
            Self::SessionRevoke => Self::SESSION_REVOKE,
            Self::SessionRead => Self::SESSION_READ,
            Self::PasswordChange => Self::PASSWORD_CHANGE,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            Self::ACCOUNT => Self::Account,
            Self::ACCOUNT_UPDATE => Self::AccountUpdate,
            Self::ACCOUNT_READ => Self::AccountRead,
            Self::SESSION => Self::Session,
            Self::SESSION_REVOKE => Self::SessionRevoke,
            Self::SESSION_READ => Self::SessionRead,
            Self::PASSWORD_CHANGE => Self::PasswordChange,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet {
    pub openid: bool,
    pub profile: bool,
    pub email: bool,
    pub address: bool,
    pub phone: bool,
    pub offline_access: bool,
    api: BTreeSet<ApiScope>,
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
                StandardScopes::ADDRESS => set.address = true,
                StandardScopes::PHONE => set.phone = true,
                StandardScopes::OFFLINE_ACCESS => set.offline_access = true,
                other if ApiScope::parse(other).is_some() => {
                    set.api
                        .insert(ApiScope::parse(other).expect("scope was checked"));
                }
                other => {
                    return Err(ScopeParseError {
                        scope_name: other.to_owned(),
                    });
                }
            }
        }

        set.normalize_api_scopes();
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
        if self.address {
            scopes.push(StandardScopes::ADDRESS);
        }
        if self.phone {
            scopes.push(StandardScopes::PHONE);
        }
        if self.offline_access {
            scopes.push(StandardScopes::OFFLINE_ACCESS);
        }
        scopes.extend(self.api.iter().copied().map(ApiScope::name));
        scopes.join(" ")
    }

    pub fn names(&self) -> Vec<&'static str> {
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
        if self.address {
            scopes.push(StandardScopes::ADDRESS);
        }
        if self.phone {
            scopes.push(StandardScopes::PHONE);
        }
        if self.offline_access {
            scopes.push(StandardScopes::OFFLINE_ACCESS);
        }
        scopes.extend(self.api.iter().copied().map(ApiScope::name));
        scopes
    }

    pub fn contains_openid(&self) -> bool {
        self.openid
    }

    #[must_use]
    pub fn allows(&self, required: ApiScope) -> bool {
        self.api.iter().copied().any(|granted| match granted {
            ApiScope::Account => matches!(
                required,
                ApiScope::Account | ApiScope::AccountUpdate | ApiScope::AccountRead
            ),
            ApiScope::AccountUpdate => {
                matches!(required, ApiScope::AccountUpdate | ApiScope::AccountRead)
            }
            ApiScope::Session => matches!(
                required,
                ApiScope::Session | ApiScope::SessionRevoke | ApiScope::SessionRead
            ),
            ApiScope::SessionRevoke => {
                matches!(required, ApiScope::SessionRevoke | ApiScope::SessionRead)
            }
            other => other == required,
        })
    }

    #[must_use]
    pub fn has_api_scopes(&self) -> bool {
        !self.api.is_empty()
    }

    fn normalize_api_scopes(&mut self) {
        if self.api.contains(&ApiScope::Account) {
            self.api.remove(&ApiScope::AccountUpdate);
            self.api.remove(&ApiScope::AccountRead);
        } else if self.api.contains(&ApiScope::AccountUpdate) {
            self.api.remove(&ApiScope::AccountRead);
        }

        if self.api.contains(&ApiScope::Session) {
            self.api.remove(&ApiScope::SessionRevoke);
            self.api.remove(&ApiScope::SessionRead);
        } else if self.api.contains(&ApiScope::SessionRevoke) {
            self.api.remove(&ApiScope::SessionRead);
        }
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
    use std::collections::BTreeSet;

    use super::{ApiScope, ScopeSet};

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
            address: false,
            phone: false,
            offline_access: true,
            api: BTreeSet::new(),
        };
        assert_eq!(scope.to_scope_string(), "openid profile offline_access");
    }

    #[test]
    fn parse_scope_with_address_and_phone() {
        let scope = ScopeSet::parse("openid address phone").unwrap();

        assert!(scope.openid);
        assert!(scope.address);
        assert!(scope.phone);
    }

    #[test]
    fn to_scope_string_includes_address_and_phone_in_standard_order() {
        let scope = ScopeSet {
            openid: true,
            profile: false,
            email: false,
            address: true,
            phone: true,
            offline_access: true,
            api: BTreeSet::new(),
        };

        assert_eq!(
            scope.to_scope_string(),
            "openid address phone offline_access"
        );
    }

    #[test]
    fn names_returns_requested_scope_names_in_standard_order() {
        let scope = ScopeSet::parse("phone openid address").unwrap();

        assert_eq!(scope.names(), vec!["openid", "address", "phone"]);
    }

    #[test]
    fn contains_openid() {
        let scope = ScopeSet::parse("openid").unwrap();
        assert!(scope.contains_openid());

        let scope_no_openid = ScopeSet::parse("profile").unwrap();
        assert!(!scope_no_openid.contains_openid());
    }

    #[test]
    fn api_parent_scopes_imply_children_and_are_normalized() {
        let scope = ScopeSet::parse("openid account account.read session session.revoke").unwrap();

        assert!(scope.allows(ApiScope::AccountRead));
        assert!(scope.allows(ApiScope::AccountUpdate));
        assert!(scope.allows(ApiScope::SessionRead));
        assert!(scope.allows(ApiScope::SessionRevoke));
        assert_eq!(scope.to_scope_string(), "openid account session");
    }

    #[test]
    fn password_change_is_standalone() {
        let scope = ScopeSet::parse("openid password.change").unwrap();

        assert!(scope.allows(ApiScope::PasswordChange));
        assert!(!scope.allows(ApiScope::AccountRead));
    }
}
