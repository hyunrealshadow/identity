use chrono::{Duration, Utc};
use serde_json::{from_slice, to_string};
use url::Url;

use super::request::DynamicClientJwks;
use crate::{
    application::error::{AppError, codes::registration},
    domain::{key::PublicJwk, openid_connect::OpenIdConnectCredentialData},
    openid_connect::remote::{DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteDocumentFetcher},
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
    remote_fetcher: &dyn RemoteDocumentFetcher,
    jwks_uri: Option<&Url>,
) -> Result<Option<OpenIdConnectCredentialData>, AppError> {
    let Some(jwks_uri) = jwks_uri else {
        return Ok(None);
    };

    let jwks = fetch_jwks(remote_fetcher, jwks_uri).await?;
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
        return Err(registration::error::InvalidClientMetadata.into_error());
    }

    Ok(())
}

async fn fetch_jwks(
    remote_fetcher: &dyn RemoteDocumentFetcher,
    jwks_uri: &Url,
) -> Result<DynamicClientJwks, AppError> {
    let body = remote_fetcher
        .fetch_https_public_document(jwks_uri, DEFAULT_REMOTE_DOCUMENT_MAX_BYTES)
        .await
        .map_err(registration::error::ClientCreateFailed::map_source())?;

    from_slice::<DynamicClientJwks>(&body)
        .map_err(registration::error::ClientCreateFailed::map_source())
}

fn public_jwk_to_pem(jwk: &PublicJwk) -> Result<String, AppError> {
    to_string(jwk).map_err(registration::error::ClientCreateFailed::map_source())
}
