use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::{
    application::error::{AppError, codes::registration::RegistrationErrorCode},
    domain::openid_connect::OpenIdConnectClient,
};

use super::request::DynamicClientJwks;

#[derive(Debug, Clone, Serialize)]
pub struct DynamicClientRegistrationResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<DynamicClientJwks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<Url>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<Url>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub(super) fn registration_client_uri(issuer: &Url, client_id: Uuid) -> Result<Url, AppError> {
    let base = issuer.as_str().trim_end_matches('/');
    Url::parse(&format!("{base}/oauth2/register/{client_id}")).map_err(|error| {
        AppError::from_code(RegistrationErrorCode::ClientLookupFailed).with_source(error)
    })
}

pub(super) fn response_from_client(
    client: &OpenIdConnectClient,
    registration_access_token: Option<String>,
    issuer: &Url,
) -> Result<DynamicClientRegistrationResponse, AppError> {
    let metadata = client.metadata();
    let platform = client.platforms().first();
    let application_type = platform.map(|value| value.platform.to_string());
    let redirect_uris = platform
        .map(|value| value.redirect_uris.clone())
        .unwrap_or_default();
    let scope = (!client.assigned_scopes().is_empty()).then(|| client.assigned_scopes().join(" "));

    Ok(DynamicClientRegistrationResponse {
        client_id: client.client().oid.to_string(),
        registration_access_token,
        registration_client_uri: Some(registration_client_uri(issuer, client.client().oid)?),
        client_secret: None,
        client_secret_expires_at: None,
        redirect_uris,
        response_types: metadata.response_types.clone(),
        grant_types: metadata.grant_types.clone(),
        application_type,
        contacts: metadata.contacts.clone(),
        client_name: Some(client.client().name.clone()),
        logo_uri: metadata.logo_uri.clone(),
        client_uri: metadata.client_uri.clone(),
        policy_uri: metadata.policy_uri.clone(),
        tos_uri: metadata.tos_uri.clone(),
        sector_identifier_uri: metadata.sector_identifier_uri.clone(),
        subject_type: metadata.subject_type.map(|value| value.to_string()),
        id_token_signed_response_alg: metadata.id_token_signed_response_alg.clone(),
        id_token_encrypted_response_alg: metadata.id_token_encrypted_response_alg.clone(),
        id_token_encrypted_response_enc: metadata.id_token_encrypted_response_enc.clone(),
        userinfo_signed_response_alg: metadata.userinfo_signed_response_alg.clone(),
        userinfo_encrypted_response_alg: metadata.userinfo_encrypted_response_alg.clone(),
        userinfo_encrypted_response_enc: metadata.userinfo_encrypted_response_enc.clone(),
        request_object_signing_alg: metadata.request_object_signing_alg.clone(),
        request_object_encryption_alg: metadata.request_object_encryption_alg.clone(),
        request_object_encryption_enc: metadata.request_object_encryption_enc.clone(),
        token_endpoint_auth_method: metadata.token_endpoint_auth_method.clone(),
        token_endpoint_auth_signing_alg: metadata.token_endpoint_auth_signing_alg.clone(),
        jwks: None,
        jwks_uri: None,
        default_max_age: metadata.default_max_age,
        require_auth_time: metadata.require_auth_time,
        default_acr_values: metadata.default_acr_values.clone(),
        initiate_login_uri: metadata.initiate_login_uri.clone(),
        request_uris: metadata.request_uris.clone(),
        post_logout_redirect_uris: metadata.post_logout_redirect_uris.clone(),
        frontchannel_logout_uri: metadata.frontchannel_logout_uri.clone(),
        frontchannel_logout_session_required: metadata.frontchannel_logout_session_required,
        backchannel_logout_uri: metadata.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: metadata.backchannel_logout_session_required,
        scope,
    })
}
