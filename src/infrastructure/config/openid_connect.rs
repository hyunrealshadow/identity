use std::fmt;

use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenIdConnectConfig {
    #[serde(default)]
    pub dynamic_registration: DynamicClientRegistrationConfig,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicClientRegistrationConfig {
    /// Optional fixed RFC 7591 initial access token used only by the OIDC
    /// conformance harness. Ordinary deployments must not use a long-lived
    /// shared token for dynamic client registration.
    #[cfg(feature = "oidc-conformance")]
    #[serde(default)]
    pub conformance_initial_access_token: Option<String>,
}

impl fmt::Debug for DynamicClientRegistrationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut state = formatter.debug_struct("DynamicClientRegistrationConfig");
        #[cfg(feature = "oidc-conformance")]
        state.field(
            "conformance_initial_access_token",
            &self
                .conformance_initial_access_token
                .as_ref()
                .map(|_| "[REDACTED]"),
        );
        state.finish()
    }
}

impl DynamicClientRegistrationConfig {
    #[must_use]
    pub fn required_conformance_initial_access_token(&self) -> Option<&str> {
        #[cfg(feature = "oidc-conformance")]
        {
            self.conformance_initial_access_token
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }
        #[cfg(not(feature = "oidc-conformance"))]
        {
            None
        }
    }
}

#[cfg(all(test, feature = "oidc-conformance"))]
mod tests {
    use super::DynamicClientRegistrationConfig;

    #[test]
    fn debug_redacts_conformance_initial_access_token() {
        let cfg = DynamicClientRegistrationConfig {
            conformance_initial_access_token: Some("super-secret-initial-access-token".to_owned()),
        };
        assert!(!format!("{cfg:?}").contains("super-secret-initial-access-token"));
    }
}
