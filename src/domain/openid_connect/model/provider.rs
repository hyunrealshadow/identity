use std::error::Error;
use std::{fmt, str::FromStr};

use serde::Serialize;
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};
use url::Url;

fn is_empty<T>(value: &Option<Vec<T>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum SubjectType {
    Public,
    Pairwise,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSubjectTypeError;

impl fmt::Display for ParseSubjectTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid subject type")
    }
}

impl Error for ParseSubjectTypeError {}

impl FromStr for SubjectType {
    type Err = ParseSubjectTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == value)
            .ok_or(ParseSubjectTypeError)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ClaimType {
    Normal,
    Aggregated,
    Distributed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid OpenID Connect claim type")]
pub struct ParseClaimTypeError;

impl FromStr for ClaimType {
    type Err = ParseClaimTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == value)
            .ok_or(ParseClaimTypeError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid token endpoint authentication method")]
pub struct ParseTokenEndpointAuthMethodError;

impl FromStr for TokenEndpointAuthMethod {
    type Err = ParseTokenEndpointAuthMethodError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|variant| variant.as_ref() == value)
            .ok_or(ParseTokenEndpointAuthMethodError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenIdProviderMetadata {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<Url>,
    pub require_pushed_authorization_requests: bool,
    /// RFC 7009 token revocation endpoint.
    pub revocation_endpoint: Url,
    pub introspection_endpoint: Url,
    pub introspection_endpoint_auth_methods_supported: Vec<String>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,
    /// RFC 8628 §4: endpoint clients post device authorization requests to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<Url>,
    pub jwks_uri: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "is_empty")]
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "is_empty")]
    pub response_modes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub grant_types_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "is_empty")]
    pub acr_values_supported: Option<Vec<String>>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "is_empty")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub display_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub claim_types_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<Url>,
    #[serde(skip_serializing_if = "is_empty")]
    pub claims_locales_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty")]
    pub ui_locales_supported: Option<Vec<String>>,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_session_iframe: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_supported: Option<bool>,
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::OpenIdProviderMetadata;

    #[test]
    fn omits_empty_optional_arrays() {
        let metadata = OpenIdProviderMetadata {
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: false,
            issuer: Url::parse("https://identity.example.com").unwrap(),
            authorization_endpoint: Url::parse("https://identity.example.com/connect/authorize")
                .unwrap(),
            token_endpoint: Some(Url::parse("https://identity.example.com/connect/token").unwrap()),
            revocation_endpoint: Url::parse("https://identity.example.com/oauth2/revoke").unwrap(),
            introspection_endpoint: Url::parse("https://identity.example.com/oauth2/introspect")
                .unwrap(),
            introspection_endpoint_auth_methods_supported: vec!["client_secret_basic".into()],
            introspection_endpoint_auth_signing_alg_values_supported: vec![],
            revocation_endpoint_auth_methods_supported: vec![],
            revocation_endpoint_auth_signing_alg_values_supported: vec![],
            userinfo_endpoint: None,
            device_authorization_endpoint: None,
            jwks_uri: Url::parse("https://identity.example.com/.well-known/keys").unwrap(),
            registration_endpoint: None,
            scopes_supported: Some(vec![]),
            response_types_supported: vec!["code".to_owned()],
            response_modes_supported: Some(vec![]),
            grant_types_supported: Some(vec![]),
            code_challenge_methods_supported: vec!["S256".to_owned()],
            acr_values_supported: Some(vec![]),
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["RS256".to_owned()],
            id_token_encryption_alg_values_supported: Some(vec![]),
            id_token_encryption_enc_values_supported: Some(vec![]),
            userinfo_signing_alg_values_supported: Some(vec![]),
            userinfo_encryption_alg_values_supported: Some(vec![]),
            userinfo_encryption_enc_values_supported: Some(vec![]),
            request_object_signing_alg_values_supported: Some(vec![]),
            request_object_encryption_alg_values_supported: Some(vec![]),
            request_object_encryption_enc_values_supported: Some(vec![]),
            token_endpoint_auth_methods_supported: Some(vec![]),
            token_endpoint_auth_signing_alg_values_supported: Some(vec![]),
            display_values_supported: Some(vec![]),
            claim_types_supported: Some(vec![]),
            claims_supported: Some(vec![]),
            service_documentation: None,
            claims_locales_supported: Some(vec![]),
            ui_locales_supported: Some(vec![]),
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: true,
            require_request_uri_registration: false,
            op_policy_uri: None,
            op_tos_uri: None,
            end_session_endpoint: None,
            check_session_iframe: None,
            frontchannel_logout_supported: None,
            frontchannel_logout_session_supported: None,
            backchannel_logout_supported: None,
            backchannel_logout_session_supported: None,
        };

        let value = serde_json::to_value(&metadata).unwrap();

        assert!(value.get("scopes_supported").is_none());
        assert!(value.get("token_endpoint_auth_methods_supported").is_none());
        assert!(value.get("claims_supported").is_none());
    }
}
