use std::{collections::BTreeSet, error::Error, fmt, str::FromStr};

use crate::authorization::catalog::{ManagementScope, is_reserved_management_name};

use super::claim::StandardScopes;

pub const API_RESOURCE: &str = "urn:identity:graphql";

#[derive(Debug, Clone, Copy)]
pub enum ResourceScopeCoverage {
    Any,
    All,
}

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
    pub const ACCOUNT: &'static str = "account.*";
    pub const ACCOUNT_UPDATE: &'static str = "account.update";
    pub const ACCOUNT_READ: &'static str = "account.read";
    pub const SESSION: &'static str = "session.*";
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

/// First segments owned by the API scope namespace. A pattern below one of
/// these namespaces is an API pattern even when the current catalog has no
/// matching leaf yet; expansion still happens only against known names.
const API_SCOPE_NAMESPACES: [&str; 3] = ["account", "session", "password"];

/// Returns the prefix of a syntactically valid trailing `.*` pattern.
///
/// A pattern is valid only when the star is the final character, follows a dot,
/// and every prefix segment is non-empty. Asterisks anywhere else are not a
/// wildcard.
fn scope_pattern_prefix(pattern: &str) -> Option<&str> {
    let prefix = pattern.strip_suffix(".*")?;
    if prefix.is_empty()
        || prefix.contains('*')
        || prefix.split('.').any(|segment| segment.is_empty())
    {
        return None;
    }
    Some(prefix)
}

/// Whether `name` is a syntactically valid trailing-`.*` scope pattern.
#[must_use]
pub fn is_scope_pattern(name: &str) -> bool {
    scope_pattern_prefix(name).is_some()
}

/// General dot-hierarchy matching between a granted name and a requested name.
///
/// - An exact granted name matches only the same exact requested name.
/// - A trailing `.*` matches every descendant at a segment boundary, but not
///   the bare prefix itself.
/// - A broader requested pattern can be covered by a still broader granted
///   pattern; an exact granted leaf can never cover an open requested pattern.
#[must_use]
pub fn scope_pattern_matches(granted: &str, requested: &str) -> bool {
    let granted_pattern = is_scope_pattern(granted);
    let requested_pattern = is_scope_pattern(requested);

    // A token containing an asterisk is either a valid trailing pattern or not
    // a usable scope name at all. It must never match as an exact literal.
    if (granted.contains('*') && !granted_pattern)
        || (requested.contains('*') && !requested_pattern)
    {
        return false;
    }

    if requested_pattern {
        return granted_pattern && pattern_covers_pattern(granted, requested);
    }
    if granted_pattern {
        return pattern_matches_name(granted, requested);
    }
    granted == requested
}

fn pattern_matches_name(pattern: &str, name: &str) -> bool {
    let Some(prefix) = scope_pattern_prefix(pattern) else {
        return false;
    };
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some(descendant) = rest.strip_prefix('.') else {
        return false;
    };
    !descendant.is_empty() && descendant.split('.').all(|segment| !segment.is_empty())
}

fn pattern_covers_pattern(granted: &str, requested: &str) -> bool {
    let (Some(granted_prefix), Some(requested_prefix)) = (
        scope_pattern_prefix(granted),
        scope_pattern_prefix(requested),
    ) else {
        return false;
    };
    if granted_prefix == requested_prefix {
        return true;
    }
    requested_prefix
        .strip_prefix(granted_prefix)
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|descendant| {
            !descendant.is_empty() && descendant.split('.').all(|segment| !segment.is_empty())
        })
}

fn is_api_scope_pattern(pattern: &str) -> bool {
    let Some(prefix) = scope_pattern_prefix(pattern) else {
        return false;
    };
    let Some(namespace) = prefix.split('.').next() else {
        return false;
    };
    API_SCOPE_NAMESPACES.contains(&namespace)
}

fn is_management_scope_pattern(pattern: &str) -> bool {
    is_reserved_management_name(pattern)
        && ManagementScope::ALL
            .iter()
            .any(|scope| scope_pattern_matches(pattern, scope.name()))
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
    /// Trusted instance-management scopes. These are deliberately kept out of
    /// `custom`: a custom scope never becomes a management grant and role
    /// names are never parsed as scopes.
    management: BTreeSet<ManagementScope>,
    /// Raw wildcard patterns. Management patterns are preserved exactly as
    /// requested and are only expanded against the trusted catalog.
    patterns: BTreeSet<String>,
    custom: BTreeSet<String>,
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
        write!(f, "invalid scope token: {}", self.scope_name)
    }
}

impl Error for ScopeParseError {}

impl ScopeSet {
    pub fn parse(scope_str: &str) -> Result<Self, ScopeParseError> {
        let mut set = Self::default();

        for scope in scope_str.split(' ').filter(|scope| !scope.is_empty()) {
            // RFC 6749 scope-token: printable ASCII except quote and backslash.
            if !scope
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            {
                return Err(ScopeParseError {
                    scope_name: scope.to_owned(),
                });
            }
            match scope {
                StandardScopes::OPENID => set.openid = true,
                StandardScopes::PROFILE => set.profile = true,
                StandardScopes::EMAIL => set.email = true,
                StandardScopes::ADDRESS => set.address = true,
                StandardScopes::PHONE => set.phone = true,
                StandardScopes::OFFLINE_ACCESS => set.offline_access = true,
                // Any asterisk must be part of a valid trailing `.*` pattern.
                // Bare `*`, embedded stars, repeated stars, empty segments and
                // other malformed wildcard shapes are rejected instead of
                // being treated as custom names.
                other if other.contains('*') => {
                    if !is_scope_pattern(other) {
                        return Err(ScopeParseError {
                            scope_name: other.to_owned(),
                        });
                    }
                    // Reserved management patterns are accepted only when they
                    // can expand from the trusted catalog. No dynamic reserved
                    // name becomes a management grant.
                    if is_reserved_management_name(other)
                        && !ManagementScope::ALL
                            .iter()
                            .any(|scope| scope_pattern_matches(other, scope.name()))
                    {
                        return Err(ScopeParseError {
                            scope_name: other.to_owned(),
                        });
                    }
                    set.patterns.insert(other.to_owned());
                }
                other if ApiScope::parse(other).is_some() => {
                    set.api
                        .insert(ApiScope::parse(other).expect("scope was checked"));
                }
                // Exact trusted-catalog lookup only. A reserved-prefix name
                // that is not in the catalog is rejected here, before any
                // database scope row or client assignment is consulted.
                other if ManagementScope::from_name(other).is_some() => {
                    set.management
                        .insert(ManagementScope::from_name(other).expect("scope was checked"));
                }
                other if is_reserved_management_name(other) => {
                    return Err(ScopeParseError {
                        scope_name: other.to_owned(),
                    });
                }
                other => {
                    set.custom.insert(other.to_owned());
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
        if self.address {
            scopes.push(StandardScopes::ADDRESS);
        }
        if self.phone {
            scopes.push(StandardScopes::PHONE);
        }
        if self.offline_access {
            scopes.push(StandardScopes::OFFLINE_ACCESS);
        }
        for scope in &self.api {
            scopes.push(scope.name());
        }
        for scope in &self.management {
            scopes.push(scope.name());
        }
        scopes.extend(self.patterns.iter().map(String::as_str));
        scopes.extend(self.custom.iter().map(String::as_str));
        scopes.join(" ")
    }

    pub fn names(&self) -> Vec<&str> {
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
        for scope in &self.api {
            scopes.push(scope.name());
        }
        for scope in &self.management {
            scopes.push(scope.name());
        }
        scopes.extend(self.patterns.iter().map(String::as_str));
        scopes.extend(self.custom.iter().map(String::as_str));
        scopes
    }

    /// Whether this set grants `name`, using literal names and general
    /// dot-hierarchy wildcard matching. Reserved management names are only
    /// recognized when they exist in the trusted catalog.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        match name {
            StandardScopes::OPENID => return self.openid,
            StandardScopes::PROFILE => return self.profile,
            StandardScopes::EMAIL => return self.email,
            StandardScopes::ADDRESS => return self.address,
            StandardScopes::PHONE => return self.phone,
            StandardScopes::OFFLINE_ACCESS => return self.offline_access,
            _ => {}
        }

        if !is_scope_pattern(name) && is_reserved_management_name(name) {
            let Some(scope) = ManagementScope::from_name(name) else {
                return false;
            };
            return self.has_management_scope(scope);
        }

        self.api.iter().any(|scope| scope.name() == name)
            || self.management.iter().any(|scope| scope.name() == name)
            || self.custom.contains(name)
            || self
                .patterns
                .iter()
                .any(|pattern| scope_pattern_matches(pattern, name))
    }

    #[must_use]
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    #[must_use]
    pub fn patterns(&self) -> Vec<&str> {
        self.patterns.iter().map(String::as_str).collect()
    }

    pub fn contains_openid(&self) -> bool {
        self.openid
    }

    pub fn contains_offline_access(&self) -> bool {
        self.offline_access
    }

    /// Trusted management scopes carried or implied by this set. Patterns are
    /// expanded only against `ManagementScope::ALL`; unknown reserved names are
    /// never synthesized.
    #[must_use]
    pub fn management_scopes(&self) -> Vec<ManagementScope> {
        let mut scopes = self.management.clone();
        for scope in ManagementScope::ALL {
            if self.patterns.iter().any(|pattern| {
                is_management_scope_pattern(pattern) && scope_pattern_matches(pattern, scope.name())
            }) {
                scopes.insert(scope);
            }
        }
        scopes.into_iter().collect()
    }

    #[must_use]
    pub fn management_scope_names(&self) -> Vec<&'static str> {
        self.management_scopes()
            .into_iter()
            .map(|scope| scope.name())
            .collect()
    }

    #[must_use]
    pub fn has_management_scopes(&self) -> bool {
        !self.management.is_empty()
            || self
                .patterns
                .iter()
                .any(|pattern| is_management_scope_pattern(pattern))
    }

    #[must_use]
    pub fn has_management_scope(&self, scope: ManagementScope) -> bool {
        self.management.contains(&scope)
            || self.patterns.iter().any(|pattern| {
                is_management_scope_pattern(pattern) && scope_pattern_matches(pattern, scope.name())
            })
    }

    /// Removes exact management scopes and management patterns; standard, API,
    /// custom names and unrelated patterns are retained unchanged.
    #[must_use]
    pub fn without_management_scopes(&self) -> Self {
        let mut result = self.clone();
        result.management.clear();
        result
            .patterns
            .retain(|pattern| !is_management_scope_pattern(pattern));
        result
    }

    /// Replaces the management subset without touching other scope categories.
    /// Existing management patterns are removed; unrelated patterns remain.
    pub fn replace_management_scopes(&mut self, scopes: impl IntoIterator<Item = ManagementScope>) {
        self.management = scopes.into_iter().collect();
        self.patterns
            .retain(|pattern| !is_management_scope_pattern(pattern));
    }

    /// Protocol controls are grant context, not resource-server permissions.
    pub fn has_resource_permissions(&self) -> bool {
        self.has_api_scopes() || self.has_management_scopes() || self.has_custom_scopes()
    }

    /// Restrict resource permissions while retaining the grant's protocol controls.
    /// `All` is required for a single access token usable at every target.
    ///
    /// Only exact leaf candidates are intersected. Wildcard patterns from this
    /// grant or from resource ceilings are not turned into grants here; the
    /// provider expands actual requests against the known catalog before
    /// issuance.
    pub fn for_resources(&self, resources: &[Self], coverage: ResourceScopeCoverage) -> Self {
        let mut candidates = self.names();
        for resource in resources {
            candidates.extend(resource.names());
        }
        let permissions = candidates
            .into_iter()
            .filter(|name| !is_scope_pattern(name))
            .filter(|name| {
                let candidate = Self::parse(name).expect("domain scope name");
                candidate.has_resource_permissions()
                    && self.covers(&candidate)
                    && match coverage {
                        ResourceScopeCoverage::Any => {
                            resources.iter().any(|set| set.covers(&candidate))
                        }
                        ResourceScopeCoverage::All => {
                            resources.iter().all(|set| set.covers(&candidate))
                        }
                    }
            })
            .collect::<Vec<_>>();
        let mut result = Self::parse(&permissions.join(" ")).expect("domain scope names");
        result.openid = self.openid;
        result.profile = self.profile;
        result.email = self.email;
        result.address = self.address;
        result.phone = self.phone;
        result.offline_access = self.offline_access;
        result
    }

    #[must_use]
    pub fn covers(&self, requested: &Self) -> bool {
        (!requested.openid || self.openid)
            && (!requested.profile || self.profile)
            && (!requested.email || self.email)
            && (!requested.address || self.address)
            && (!requested.phone || self.phone)
            && (!requested.offline_access || self.offline_access)
            && requested.api.iter().all(|scope| self.matches(scope.name()))
            && requested
                .management
                .iter()
                .all(|scope| self.has_management_scope(*scope))
            && requested.custom.iter().all(|name| self.matches(name))
            && requested
                .patterns
                .iter()
                .all(|pattern| self.matches(pattern))
    }

    #[must_use]
    pub fn allows(&self, required: ApiScope) -> bool {
        self.matches(required.name())
    }

    #[must_use]
    pub fn has_api_scopes(&self) -> bool {
        !self.api.is_empty()
            || self
                .patterns
                .iter()
                .any(|pattern| is_api_scope_pattern(pattern))
    }

    pub fn has_custom_scopes(&self) -> bool {
        !self.custom.is_empty()
            || self.patterns.iter().any(|pattern| {
                !is_api_scope_pattern(pattern) && !is_management_scope_pattern(pattern)
            })
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

    use crate::authorization::catalog::ManagementScope;

    use super::{
        ApiScope, ResourceScopeCoverage, ScopeSet, is_scope_pattern, scope_pattern_matches,
    };

    #[test]
    fn resource_coverage_preserves_controls_and_intersects_exact_leaves() {
        let granted =
            ScopeSet::parse("openid profile email address phone offline_access account.*").unwrap();
        let resources = [
            ScopeSet::parse("account.* email").unwrap(),
            ScopeSet::parse("account.read").unwrap(),
        ];
        assert_eq!(
            granted
                .for_resources(&resources, ResourceScopeCoverage::All)
                .to_scope_string(),
            "openid profile email address phone offline_access account.read"
        );
        assert_eq!(
            granted
                .for_resources(&resources, ResourceScopeCoverage::Any)
                .to_scope_string(),
            "openid profile email address phone offline_access account.read"
        );
        let controls =
            ScopeSet::parse("openid profile email address phone offline_access").unwrap();
        assert!(!controls.has_resource_permissions());
        assert_eq!(
            granted.for_resources(&[ScopeSet::default()], ResourceScopeCoverage::All),
            controls
        );
    }

    #[test]
    fn resource_intersection_does_not_manufacture_wildcards() {
        let granted = ScopeSet::parse("openid account.* orders.*").unwrap();
        assert_eq!(
            granted
                .for_resources(
                    &[ScopeSet::parse("account.read orders.read").unwrap()],
                    ResourceScopeCoverage::All,
                )
                .to_scope_string(),
            "openid account.read orders.read"
        );
        // A pattern-only ceiling yields no manufactured wildcard grant.
        assert_eq!(
            granted
                .for_resources(
                    &[ScopeSet::parse("account.* orders.*").unwrap()],
                    ResourceScopeCoverage::All,
                )
                .to_scope_string(),
            "openid"
        );
        // Exact leaves may still intersect a pattern ceiling.
        let exact = ScopeSet::parse("openid account.read orders.read").unwrap();
        assert_eq!(
            exact
                .for_resources(
                    &[ScopeSet::parse("account.* orders.*").unwrap()],
                    ResourceScopeCoverage::All,
                )
                .to_scope_string(),
            "openid account.read orders.read"
        );
    }

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
    fn custom_scopes_round_trip_and_use_exact_matching() {
        let scope = ScopeSet::parse("openid orders.read orders.read orders").unwrap();
        assert_eq!(scope.to_scope_string(), "openid orders orders.read");
        assert!(scope.covers(&ScopeSet::parse("orders.read").unwrap()));
        assert!(
            !ScopeSet::parse("orders")
                .unwrap()
                .covers(&ScopeSet::parse("orders.read").unwrap())
        );
        let selected = scope.for_resources(
            &[ScopeSet::parse("orders.read").unwrap()],
            ResourceScopeCoverage::All,
        );
        assert_eq!(selected.to_scope_string(), "openid orders.read");
        for invalid in ["orders\tread", "orders\\read", "orders\"read", "订单"] {
            assert!(ScopeSet::parse(invalid).is_err());
        }
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
            management: BTreeSet::new(),
            patterns: BTreeSet::new(),
            custom: BTreeSet::new(),
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
            management: BTreeSet::new(),
            patterns: BTreeSet::new(),
            custom: BTreeSet::new(),
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
    fn wildcard_patterns_match_descendants_at_segment_boundaries() {
        let scope =
            ScopeSet::parse("account.* session.* management.user.* orders.items.*").unwrap();

        assert!(scope.has_patterns());
        assert_eq!(
            scope.patterns(),
            vec![
                "account.*",
                "management.user.*",
                "orders.items.*",
                "session.*"
            ]
        );
        assert!(scope.matches("account.read"));
        assert!(scope.matches("account.update.deep"));
        assert!(!scope.matches("account"));
        assert!(!scope.matches("account."));
        assert!(!scope.matches("accountish.read"));
        assert!(!scope.matches("accounting.read"));
        assert!(scope.matches("session.revoke"));
        assert!(scope.matches("orders.items.create"));
        assert!(!scope.matches("orders.item.create"));
        assert!(!scope.matches("orders.items"));
    }

    #[test]
    fn wildcard_matching_supports_any_prefix_depth() {
        let broad = ScopeSet::parse("catalog.*").unwrap();
        assert!(broad.matches("catalog.products.read"));
        assert!(broad.matches("catalog.products.variants.read"));
        assert!(!broad.matches("catalog"));
        assert!(broad.covers(&ScopeSet::parse("catalog.products.*").unwrap()));
        assert!(scope_pattern_matches("catalog.*", "catalog.products.*"));
        assert!(!scope_pattern_matches("catalog.products.*", "catalog.*"));

        let narrow = ScopeSet::parse("catalog.products.*").unwrap();
        assert!(narrow.matches("catalog.products.read"));
        assert!(narrow.matches("catalog.products.variants.read"));
        assert!(!narrow.matches("catalog.orders.read"));
    }

    #[test]
    fn literal_leaves_do_not_inherit_or_cover_open_patterns() {
        let scope = ScopeSet::parse("account.update session.revoke").unwrap();
        assert!(scope.allows(ApiScope::AccountUpdate));
        assert!(!scope.allows(ApiScope::AccountRead));
        assert!(scope.allows(ApiScope::SessionRevoke));
        assert!(!scope.allows(ApiScope::SessionRead));

        let exact = ScopeSet::parse("account.read").unwrap();
        assert!(exact.matches("account.read"));
        assert!(!exact.matches("account"));
        assert!(!exact.matches("account.update"));
        assert!(!exact.covers(&ScopeSet::parse("account.*").unwrap()));
    }

    #[test]
    fn api_wildcard_constants_and_password_pattern() {
        assert_eq!(ApiScope::ACCOUNT, "account.*");
        assert_eq!(ApiScope::SESSION, "session.*");

        let scope = ScopeSet::parse("openid account.* session.* password.*").unwrap();
        assert!(scope.has_api_scopes());
        assert!(scope.allows(ApiScope::AccountRead));
        assert!(scope.allows(ApiScope::AccountUpdate));
        assert!(scope.allows(ApiScope::SessionRead));
        assert!(scope.allows(ApiScope::SessionRevoke));
        assert!(scope.allows(ApiScope::PasswordChange));
        assert_eq!(
            scope.to_scope_string(),
            "openid account.* password.* session.*"
        );
    }

    #[test]
    fn bare_account_and_session_are_not_api_aliases() {
        for name in ["account", "session"] {
            let scope = ScopeSet::parse(name).unwrap();
            assert!(!scope.has_api_scopes(), "{name}");
            assert!(scope.has_custom_scopes(), "{name}");
            assert_eq!(scope.to_scope_string(), name);
        }
        assert!(ScopeSet::parse("account.*").unwrap().has_api_scopes());
        assert!(ScopeSet::parse("session.*").unwrap().has_api_scopes());
    }

    #[test]
    fn covers_subset_and_hierarchical_wildcard_scopes() {
        let granted = ScopeSet::parse("openid profile account.*").unwrap();

        assert!(granted.covers(&ScopeSet::parse("openid").unwrap()));
        assert!(granted.covers(&ScopeSet::parse("openid account.read").unwrap()));
        assert!(granted.covers(&ScopeSet::parse("openid account.update").unwrap()));
        assert!(!granted.covers(&ScopeSet::parse("openid account").unwrap()));
        assert!(!granted.covers(&ScopeSet::parse("openid email").unwrap()));
    }

    #[test]
    fn management_scopes_are_exact_and_separate_from_custom_scopes() {
        let scope = ScopeSet::parse("openid management.user.read management.audit.read").unwrap();
        assert!(scope.has_management_scopes());
        assert_eq!(
            scope.management_scopes(),
            vec![ManagementScope::UsersRead, ManagementScope::AuditRead]
        );
        assert!(scope.has_management_scope(ManagementScope::UsersRead));
        assert!(!scope.has_management_scope(ManagementScope::UsersCreate));
        assert!(!scope.has_custom_scopes());
        assert!(scope.has_resource_permissions());
        assert_eq!(
            scope.to_scope_string(),
            "openid management.user.read management.audit.read"
        );
        assert_eq!(
            scope.without_management_scopes().to_scope_string(),
            "openid"
        );
    }

    #[test]
    fn management_patterns_expand_only_from_the_trusted_catalog() {
        let scope = ScopeSet::parse("openid management.* orders.*").unwrap();
        assert!(scope.has_management_scopes());
        assert_eq!(scope.management_scopes().len(), ManagementScope::ALL.len());
        assert_eq!(
            scope.management_scope_names().len(),
            ManagementScope::ALL.len()
        );
        assert!(scope.has_management_scope(ManagementScope::UsersRead));
        assert!(scope.has_management_scope(ManagementScope::PermissionDelegate));
        assert!(!scope.matches("management.unknown"));
        assert!(scope.matches("management.user.read"));

        let users = ScopeSet::parse("management.user.*").unwrap();
        assert_eq!(
            users.management_scopes(),
            vec![
                ManagementScope::UsersRead,
                ManagementScope::UsersCreate,
                ManagementScope::UsersUpdate,
                ManagementScope::UsersState,
                ManagementScope::UsersRevokeAccess,
            ]
        );
        assert!(!users.has_management_scope(ManagementScope::ClientsRead));
    }

    #[test]
    fn management_pattern_removal_and_replacement_preserve_other_patterns() {
        let scope = ScopeSet::parse("openid management.* management.audit.read orders.*").unwrap();

        let without = scope.without_management_scopes();
        assert!(!without.has_management_scopes());
        assert_eq!(without.patterns(), vec!["orders.*"]);
        assert!(!without.matches("management.user.read"));
        assert!(without.matches("orders.read"));
        assert!(without.contains_openid());

        let mut replaced = scope;
        replaced.replace_management_scopes([ManagementScope::UsersRead]);
        assert_eq!(
            replaced.management_scopes(),
            vec![ManagementScope::UsersRead]
        );
        assert_eq!(replaced.patterns(), vec!["orders.*"]);
        assert!(replaced.has_management_scope(ManagementScope::UsersRead));
        assert!(!replaced.has_management_scope(ManagementScope::AuditRead));
        assert!(replaced.matches("orders.read"));
    }

    #[test]
    fn reserved_prefix_names_outside_the_catalog_are_rejected() {
        for invalid in [
            "management.users",
            "management.user.read.extra",
            "management.unknown",
            "management.",
            "management.unknown.*",
            "management.user.read.*",
        ] {
            assert!(ScopeSet::parse(invalid).is_err(), "{invalid}");
        }
        // A non-reserved similarly spelled name remains an ordinary custom scope.
        let custom = ScopeSet::parse("managementx.users.read managementx.*").unwrap();
        assert!(custom.has_custom_scopes());
        assert!(!custom.has_management_scopes());
        assert_eq!(custom.patterns(), vec!["managementx.*"]);
    }

    #[test]
    fn covers_management_scopes_exactly_and_through_patterns() {
        let granted = ScopeSet::parse("openid management.user.read").unwrap();
        assert!(granted.covers(&ScopeSet::parse("management.user.read").unwrap()));
        assert!(!granted.covers(&ScopeSet::parse("management.user.create").unwrap()));
        assert!(!granted.covers(&ScopeSet::parse("management.user.*").unwrap()));
        assert!(ScopeSet::parse("management.users").is_err());

        let wildcard = ScopeSet::parse("management.user.*").unwrap();
        assert!(wildcard.covers(&ScopeSet::parse("management.user.read").unwrap()));
        assert!(wildcard.covers(&ScopeSet::parse("management.user.create").unwrap()));
        assert!(!wildcard.covers(&ScopeSet::parse("management.client.read").unwrap()));
        assert!(!wildcard.covers(&ScopeSet::parse("management.*").unwrap()));
        assert!(
            ScopeSet::parse("management.*")
                .unwrap()
                .covers(&ScopeSet::parse("management.user.*").unwrap())
        );
    }

    #[test]
    fn custom_patterns_are_preserved_separately_from_custom_leaves() {
        let scope = ScopeSet::parse("orders.* orders.read").unwrap();
        assert!(scope.has_patterns());
        assert_eq!(scope.patterns(), vec!["orders.*"]);
        assert!(scope.has_custom_scopes());
        assert!(scope.matches("orders.read"));
        assert!(scope.matches("orders.items.read"));
        assert!(!scope.matches("orders"));
        assert!(scope.covers(&ScopeSet::parse("orders.items.*").unwrap()));
        assert_eq!(scope.names(), vec!["orders.*", "orders.read"]);
        assert_eq!(scope.to_scope_string(), "orders.* orders.read");
    }

    #[test]
    fn malformed_wildcards_are_rejected() {
        for invalid in [
            "*",
            "account*",
            "account.**",
            "account.*.*",
            "account.*.read",
            "account..*",
            ".*",
            "..*",
            "management.*.*",
            "management..*",
        ] {
            assert!(ScopeSet::parse(invalid).is_err(), "{invalid}");
        }
        for valid in [
            "account.*",
            "a.b.c.*",
            "orders.*",
            "management.*",
            "management.user.*",
        ] {
            assert!(is_scope_pattern(valid), "{valid}");
            assert!(ScopeSet::parse(valid).is_ok(), "{valid}");
        }
        assert!(!is_scope_pattern("account"));
        assert!(!is_scope_pattern("account.read"));
        assert!(!is_scope_pattern("*"));
    }

    #[test]
    fn matches_recognizes_standard_and_custom_names() {
        let scope = ScopeSet::parse("openid profile orders.read").unwrap();
        assert!(scope.matches("openid"));
        assert!(scope.matches("profile"));
        assert!(!scope.matches("email"));
        assert!(scope.matches("orders.read"));
        assert!(!scope.matches("orders"));
    }
}
