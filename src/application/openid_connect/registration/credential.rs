use chrono::{Duration, Utc};
use url::Url;

use crate::{
    application::error::{AppError, codes::registration::RegistrationErrorCode},
    domain::{key::PublicJwk, openid_connect::OpenIdConnectCredentialData},
    openid_connect::remote::{
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
        fetch_https_public_document, remote_http_client,
    },
};

use super::request::DynamicClientJwks;

pub(super) fn client_credentials_from_jwks(
    jwks: Option<&DynamicClientJwks>,
) -> Result<Vec<OpenIdConnectCredentialData>, AppError> {
    let Some(jwks) = jwks else {
        return Ok(Vec::new());
    };

    jwks.keys
        .iter()
        .map(|jwk| {
            public_jwk_to_pem(jwk).map(|public_key| OpenIdConnectCredentialData::ClientPublicKey {
                public_key,
                jwk: Some(jwk.clone()),
            })
        })
        .collect()
}

pub(super) async fn client_credentials_from_jwks_uri(
    jwks_uri: Option<&Url>,
) -> Result<Option<OpenIdConnectCredentialData>, AppError> {
    let Some(jwks_uri) = jwks_uri else {
        return Ok(None);
    };

    let jwks = fetch_jwks(jwks_uri).await?;
    let public_keys = jwks
        .keys
        .iter()
        .map(public_jwk_to_pem)
        .collect::<Result<Vec<_>, _>>()?;
    let now = Utc::now();

    Ok(Some(OpenIdConnectCredentialData::ClientJsonWebKeySet {
        jwks_uri: jwks_uri.clone(),
        last_updated: now,
        expires_at: now + Duration::hours(1),
        public_keys,
        jwks: jwks.keys,
    }))
}

async fn fetch_jwks(jwks_uri: &Url) -> Result<DynamicClientJwks, AppError> {
    let client = remote_http_client(RemoteFetchPolicy::new(
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        std::time::Duration::from_secs(5),
        conformance_allows_invalid_certs(),
    ))
    .map_err(|error| {
        AppError::from_code(RegistrationErrorCode::ClientCreateFailed).with_source(error)
    })?;

    let body = fetch_https_public_document(&client, jwks_uri, DEFAULT_REMOTE_DOCUMENT_MAX_BYTES)
        .await
        .map_err(|error| {
            AppError::from_code(RegistrationErrorCode::ClientCreateFailed).with_source(error)
        })?;

    serde_json::from_slice::<DynamicClientJwks>(&body).map_err(|error| {
        AppError::from_code(RegistrationErrorCode::ClientCreateFailed).with_source(error)
    })
}

fn public_jwk_to_pem(jwk: &PublicJwk) -> Result<String, AppError> {
    serde_json::to_string(jwk).map_err(|error| {
        AppError::from_code(RegistrationErrorCode::ClientCreateFailed).with_source(error)
    })
}
