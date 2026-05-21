use serde::{Deserialize, Serialize};
use url::Url;

use crate::domain::key::PublicJwk;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Vec<Url>,
    pub response_types: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub application_type: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub client_name: Option<String>,
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
    pub jwks: Option<DynamicClientJwks>,
    pub jwks_uri: Option<Url>,
    pub default_max_age: Option<i32>,
    pub require_auth_time: Option<bool>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<Url>,
    pub request_uris: Option<Vec<Url>>,
    pub post_logout_redirect_uris: Option<Vec<Url>>,
    pub frontchannel_logout_uri: Option<Url>,
    pub frontchannel_logout_session_required: Option<bool>,
    pub backchannel_logout_uri: Option<Url>,
    pub backchannel_logout_session_required: Option<bool>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicClientJwks {
    pub keys: Vec<PublicJwk>,
}
