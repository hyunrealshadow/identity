use url::Url;

use crate::domain::client::model::Client;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenIdConnectClientMetadata {
    pub redirect_uris: Option<Vec<Url>>,
    pub post_logout_redirect_uris: Option<Vec<Url>>,
    pub response_types: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub application_type: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub logo_uri: Option<Url>,
    pub client_uri: Option<Url>,
    pub policy_uri: Option<Url>,
    pub tos_uri: Option<Url>,
    pub sector_identifier_uri: Option<Url>,
    pub subject_type: Option<String>,
    pub id_token_signed_response_alg: Option<String>,
    pub id_token_encrypted_response_alg: Option<String>,
    pub id_token_encrypted_response_enc: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub request_object_signing_alg: Option<String>,
    pub request_object_encryption_alg: Option<String>,
    pub request_object_encryption_enc: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub default_max_age: Option<i32>,
    pub require_auth_time: Option<bool>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<Url>,
    pub request_uris: Option<Vec<Url>>,
    pub skip_consent: bool,
}

#[derive(Debug, Clone)]
pub struct OpenIdConnectClient {
    client: Client,
    metadata: OpenIdConnectClientMetadata,
    assigned_scopes: Vec<String>,
}

impl OpenIdConnectClient {
    pub fn new(
        client: Client,
        metadata: OpenIdConnectClientMetadata,
        assigned_scopes: Vec<String>,
    ) -> Result<Self, InvalidOpenIdConnectClientError> {
        if client.protocol != crate::domain::client::model::ClientProtocol::OpenIdConnect {
            return Err(InvalidOpenIdConnectClientError);
        }

        Ok(Self {
            client,
            metadata,
            assigned_scopes,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn metadata(&self) -> &OpenIdConnectClientMetadata {
        &self.metadata
    }

    pub fn assigned_scopes(&self) -> &[String] {
        &self.assigned_scopes
    }

    pub fn has_assigned_scope(&self, scope_name: &str) -> bool {
        self.assigned_scopes
            .iter()
            .any(|assigned| assigned == scope_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOpenIdConnectClientError;

impl std::fmt::Display for InvalidOpenIdConnectClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client protocol must be openid_connect")
    }
}

impl std::error::Error for InvalidOpenIdConnectClientError {}

#[cfg(test)]
mod tests {
    use super::{OpenIdConnectClient, OpenIdConnectClientMetadata};
    use crate::domain::client::model::{Client, ClientProtocol};
    use chrono::Utc;
    use url::Url;

    #[test]
    fn stores_redirect_and_logout_metadata() {
        let metadata = OpenIdConnectClientMetadata {
            redirect_uris: Some(vec![Url::parse("https://rp.example.com/callback").unwrap()]),
            post_logout_redirect_uris: Some(vec![
                Url::parse("https://rp.example.com/logout/callback").unwrap(),
            ]),
            response_types: Some(vec!["code".to_string()]),
            grant_types: Some(vec!["authorization_code".to_string()]),
            application_type: Some("web".to_string()),
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            skip_consent: false,
        };

        assert_eq!(
            metadata.redirect_uris.unwrap()[0].as_str(),
            "https://rp.example.com/callback"
        );
    }

    #[test]
    fn stores_client_and_metadata_together() {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::OpenIdConnect,
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            created_at: Utc::now(),
            updated_at: None,
        };

        let metadata = OpenIdConnectClientMetadata {
            redirect_uris: Some(vec![Url::parse("https://rp.example.com/callback").unwrap()]),
            post_logout_redirect_uris: None,
            response_types: None,
            grant_types: None,
            application_type: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            skip_consent: false,
        };

        let oidc_client = OpenIdConnectClient::new(client, metadata, vec![]).unwrap();

        assert_eq!(
            oidc_client.metadata().redirect_uris.as_ref().unwrap()[0].as_str(),
            "https://rp.example.com/callback"
        );
    }

    #[test]
    fn rejects_non_openid_connect_clients() {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::Other("saml".to_string()),
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            created_at: Utc::now(),
            updated_at: None,
        };

        let metadata = OpenIdConnectClientMetadata {
            redirect_uris: None,
            post_logout_redirect_uris: None,
            response_types: None,
            grant_types: None,
            application_type: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            skip_consent: false,
        };

        assert!(OpenIdConnectClient::new(client, metadata, vec![]).is_err());
    }

    #[test]
    fn stores_skip_consent_flag() {
        let metadata = OpenIdConnectClientMetadata {
            redirect_uris: None,
            post_logout_redirect_uris: None,
            response_types: None,
            grant_types: None,
            application_type: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            skip_consent: true,
        };

        assert_eq!(metadata.skip_consent, true);
    }

    #[test]
    fn stores_assigned_scope_names() {
        let client = Client {
            oid: uuid::Uuid::nil(),
            protocol: ClientProtocol::OpenIdConnect,
            name: "Example RP".to_string(),
            names: vec![],
            description: None,
            created_at: Utc::now(),
            updated_at: None,
        };
        let metadata = OpenIdConnectClientMetadata {
            redirect_uris: None,
            post_logout_redirect_uris: None,
            response_types: None,
            grant_types: None,
            application_type: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            skip_consent: false,
        };

        let oidc_client = OpenIdConnectClient::new(
            client,
            metadata,
            vec!["openid".to_string(), "email".to_string()],
        )
        .unwrap();

        assert!(oidc_client.has_assigned_scope("openid"));
        assert!(oidc_client.has_assigned_scope("email"));
        assert!(!oidc_client.has_assigned_scope("profile"));
    }
}
