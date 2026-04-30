use std::{fmt, str::FromStr};

use serde::Serialize;
use url::Url;

fn is_empty<T>(value: &Option<Vec<T>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectType {
    Public,
    Pairwise,
}

impl fmt::Display for SubjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Public => "public",
            Self::Pairwise => "pairwise",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSubjectTypeError;

impl fmt::Display for ParseSubjectTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid subject type")
    }
}

impl std::error::Error for ParseSubjectTypeError {}

impl FromStr for SubjectType {
    type Err = ParseSubjectTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "public" => Self::Public,
            "pairwise" => Self::Pairwise,
            _ => return Err(ParseSubjectTypeError),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
}

impl fmt::Display for TokenEndpointAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenIdProviderMetadata {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,
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
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use url::Url;

    use super::{OpenIdProviderMetadata, SubjectType};

    #[test]
    fn serializes_required_fields_and_explicit_booleans() {
        let metadata = OpenIdProviderMetadata {
            issuer: Url::parse("https://identity.example.com").unwrap(),
            authorization_endpoint: Url::parse("https://identity.example.com/connect/authorize")
                .unwrap(),
            token_endpoint: Some(Url::parse("https://identity.example.com/connect/token").unwrap()),
            userinfo_endpoint: Some(
                Url::parse("https://identity.example.com/connect/userinfo").unwrap(),
            ),
            jwks_uri: Url::parse("https://identity.example.com/.well-known/keys").unwrap(),
            registration_endpoint: Some(
                Url::parse("https://identity.example.com/connect/register").unwrap(),
            ),
            scopes_supported: Some(vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "offline_access".to_owned(),
            ]),
            response_types_supported: vec!["code".to_owned(), "id_token".to_owned()],
            response_modes_supported: Some(vec!["query".to_owned(), "fragment".to_owned()]),
            grant_types_supported: Some(vec![
                "authorization_code".to_owned(),
                "implicit".to_owned(),
                "refresh_token".to_owned(),
            ]),
            acr_values_supported: None,
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["RS256".to_owned()],
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: None,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: Some(vec![
                "none".to_owned(),
                "RS256".to_owned(),
            ]),
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_owned()]),
            token_endpoint_auth_signing_alg_values_supported: Some(vec!["RS256".to_owned()]),
            display_values_supported: Some(vec!["page".to_owned()]),
            claim_types_supported: Some(vec!["normal".to_owned()]),
            claims_supported: Some(vec!["sub".to_owned(), "iss".to_owned()]),
            service_documentation: Some(
                Url::parse("https://identity.example.com/docs/openid-connect").unwrap(),
            ),
            claims_locales_supported: Some(vec!["en-US".to_owned()]),
            ui_locales_supported: Some(vec!["en-US".to_owned()]),
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: true,
            require_request_uri_registration: false,
            op_policy_uri: Some(Url::parse("https://identity.example.com/policy").unwrap()),
            op_tos_uri: Some(Url::parse("https://identity.example.com/terms").unwrap()),
            end_session_endpoint: Some(
                Url::parse("https://identity.example.com/connect/endsession").unwrap(),
            ),
        };

        let value = serde_json::to_value(&metadata).unwrap();

        assert_eq!(value["issuer"], json!("https://identity.example.com/"));
        assert_eq!(value["claims_parameter_supported"], json!(false));
        assert_eq!(value["request_parameter_supported"], json!(false));
        assert_eq!(value["request_uri_parameter_supported"], json!(true));
        assert_eq!(
            value["response_types_supported"],
            json!(["code", "id_token"])
        );
    }

    #[test]
    fn subject_type_serializes_to_discovery_value() {
        assert_eq!(SubjectType::Public.to_string(), "public");
        assert_eq!(SubjectType::Pairwise.to_string(), "pairwise");
    }

    #[test]
    fn omits_empty_optional_arrays() {
        let metadata = OpenIdProviderMetadata {
            issuer: Url::parse("https://identity.example.com").unwrap(),
            authorization_endpoint: Url::parse("https://identity.example.com/connect/authorize")
                .unwrap(),
            token_endpoint: Some(Url::parse("https://identity.example.com/connect/token").unwrap()),
            userinfo_endpoint: None,
            jwks_uri: Url::parse("https://identity.example.com/.well-known/keys").unwrap(),
            registration_endpoint: None,
            scopes_supported: Some(vec![]),
            response_types_supported: vec!["code".to_owned()],
            response_modes_supported: Some(vec![]),
            grant_types_supported: Some(vec![]),
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
        };

        let value = serde_json::to_value(&metadata).unwrap();

        assert!(value.get("scopes_supported").is_none());
        assert!(value.get("token_endpoint_auth_methods_supported").is_none());
        assert!(value.get("claims_supported").is_none());
    }
}
