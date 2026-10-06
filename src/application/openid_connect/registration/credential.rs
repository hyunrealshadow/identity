use std::time::Duration as TimeDuration;

use chrono::{Duration, Utc};
use serde_json::{from_slice, to_string};
use url::Url;

use super::request::DynamicClientJwks;
use crate::{
    application::error::{AppError, codes::registration::RegistrationErrorCode},
    domain::{key::PublicJwk, openid_connect::OpenIdConnectCredentialData},
    openid_connect::remote::{
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
        fetch_https_public_document, remote_http_client,
    },
};

pub(super) fn client_credentials_from_jwks(
    jwks: Option<&DynamicClientJwks>,
) -> Result<Vec<OpenIdConnectCredentialData>, AppError> {
    let Some(jwks) = jwks else {
        return Ok(Vec::new());
    };
    reject_none_jwk_alg(jwks)?;

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
    reject_none_jwk_alg(&jwks)?;
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

fn reject_none_jwk_alg(jwks: &DynamicClientJwks) -> Result<(), AppError> {
    if !cfg!(feature = "allow-none-alg")
        && jwks.keys.iter().any(|jwk| jwk.algorithm() == Some("none"))
    {
        return Err(
            AppError::from_code(RegistrationErrorCode::InvalidClientMetadata)
                .with_param("field", "jwks"),
        );
    }

    Ok(())
}

async fn fetch_jwks(jwks_uri: &Url) -> Result<DynamicClientJwks, AppError> {
    let client = remote_http_client(RemoteFetchPolicy::new(
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        TimeDuration::from_secs(5),
        conformance_allows_invalid_certs(),
    ))
    .map_err(AppError::map_source(
        RegistrationErrorCode::ClientCreateFailed,
    ))?;

    let body = fetch_https_public_document(&client, jwks_uri, DEFAULT_REMOTE_DOCUMENT_MAX_BYTES)
        .await
        .map_err(AppError::map_source(
            RegistrationErrorCode::ClientCreateFailed,
        ))?;

    from_slice::<DynamicClientJwks>(&body).map_err(AppError::map_source(
        RegistrationErrorCode::ClientCreateFailed,
    ))
}

fn public_jwk_to_pem(jwk: &PublicJwk) -> Result<String, AppError> {
    to_string(jwk).map_err(AppError::map_source(
        RegistrationErrorCode::ClientCreateFailed,
    ))
}
