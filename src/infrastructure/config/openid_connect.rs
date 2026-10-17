use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenIdConnectConfig {
    #[serde(default)]
    pub dynamic_registration: DynamicClientRegistrationConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicClientRegistrationConfig {
    /// Optional fixed RFC 7591 initial access token used only by the OIDC
    /// conformance harness. Ordinary deployments must not use a long-lived
    /// shared token for dynamic client registration.
    #[cfg(feature = "oidc-conformance")]
    #[serde(default)]
    pub conformance_initial_access_token: Option<String>,
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
