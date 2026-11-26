//! Resolving inline or registered remote Request Objects and locating their client.

use super::{AuthorizationRequestParams, AuthorizeService};
use crate::{
    error::{AppError, codes::authorize},
    openid_connect::remote::{
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchError, RemoteUrlError,
        fetch_https_public_document, validate_https_public_url,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use identity_domain::openid_connect::OpenIdConnectClient;
use serde_json::{Value, from_slice};
use url::Url;

mod crypto;
mod parameters;

impl AuthorizeService {
    pub(super) async fn resolve_request_object(
        &self,
        client: &OpenIdConnectClient,
        params: &AuthorizationRequestParams,
    ) -> Result<Option<String>, AppError> {
        if let Some(request) = params.request.clone() {
            return Ok(Some(request));
        }

        if let Some(request_uri) = params.request_uri.clone() {
            let request_uri = Url::parse(&request_uri)
                .map_err(authorize::error::RequestUriInvalid::map_source())?;
            self.validate_request_uri(client, &request_uri)?;
            let raw_request_object = self.fetch_request_object(&request_uri).await?;
            return Ok(Some(raw_request_object));
        }

        Ok(None)
    }

    fn validate_request_uri(
        &self,
        client: &OpenIdConnectClient,
        request_uri: &Url,
    ) -> Result<(), AppError> {
        validate_https_public_url(request_uri).map_err(|error| match error {
            RemoteUrlError::NotHttps => authorize::error::RequestUriNotHttps.into_error(),
            RemoteUrlError::UnsafeHost => authorize::error::RequestUriUnsafeHost.into_error(),
        })?;

        let registered = client
            .metadata()
            .request_uris
            .as_ref()
            .map(|uris| uris.iter().any(|uri| uri == request_uri))
            .unwrap_or(false);

        if !registered {
            return Err(authorize::error::RequestUriNotRegistered.into_error());
        }

        Ok(())
    }

    pub(super) async fn fetch_request_object(&self, request_uri: &Url) -> Result<String, AppError> {
        let body = fetch_https_public_document(
            &self.http_client,
            request_uri,
            DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        )
        .await
        .map_err(map_request_uri_fetch_error)?;

        String::from_utf8(body).map_err(authorize::error::RequestUriReadFailed::map_source())
    }

    pub(crate) fn extract_request_object_client_id(raw: &str) -> Result<Option<String>, AppError> {
        let payload = Self::decode_request_object_payload_unverified(raw)?;
        Ok(payload
            .get("client_id")
            .and_then(|value| value.as_str())
            .map(str::to_owned))
    }

    fn decode_request_object_payload_unverified(raw: &str) -> Result<Value, AppError> {
        let payload_segment = raw
            .split('.')
            .nth(1)
            .ok_or_else(|| authorize::error::RequestObjectEncodingInvalid.into_error())?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_segment)
            .map_err(authorize::error::RequestObjectBase64Invalid::map_source())?;

        from_slice::<Value>(&payload)
            .map_err(authorize::error::RequestObjectPayloadInvalid::map_source())
    }
}

fn map_request_uri_fetch_error(error: RemoteFetchError) -> AppError {
    match error {
        RemoteFetchError::NotHttps => authorize::error::RequestUriNotHttps.into_error(),
        RemoteFetchError::UnsafeHost => authorize::error::RequestUriUnsafeHost.into_error(),
        RemoteFetchError::FetchFailed(error) => {
            authorize::error::RequestUriFetchFailed.with_source(error)
        }
        RemoteFetchError::ResolveFailed(error) => {
            authorize::error::RequestUriUnsafeHost.with_source(error)
        }
        RemoteFetchError::NotOk => authorize::error::RequestUriNot200.into_error(),
        RemoteFetchError::TooLarge => authorize::error::RequestUriTooLarge.into_error(),
        RemoteFetchError::ReadFailed(error) => {
            authorize::error::RequestUriReadFailed.with_source(error)
        }
    }
}
