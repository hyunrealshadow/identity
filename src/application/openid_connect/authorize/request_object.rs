//! Resolving inline or registered remote Request Objects and locating their client.

use super::{AuthorizationRequestParams, AuthorizeService};
#[cfg(test)]
use crate::openid_connect::remote::fetchable_url;
use crate::{
    error::{AppError, codes::authorize::AuthorizeErrorCode},
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
                .map_err(AppError::map_source(AuthorizeErrorCode::RequestUriInvalid))?;
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
            RemoteUrlError::NotHttps => AppError::from_code(AuthorizeErrorCode::RequestUriNotHttps),
            RemoteUrlError::UnsafeHost => {
                AppError::from_code(AuthorizeErrorCode::RequestUriUnsafeHost)
            }
        })?;

        let registered = client
            .metadata()
            .request_uris
            .as_ref()
            .map(|uris| uris.iter().any(|uri| uri == request_uri))
            .unwrap_or(false);

        if !registered {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestUriNotRegistered,
            ));
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

        String::from_utf8(body).map_err(AppError::map_source(
            AuthorizeErrorCode::RequestUriReadFailed,
        ))
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
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::RequestObjectEncodingInvalid))?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_segment)
            .map_err(AppError::map_source(
                AuthorizeErrorCode::RequestObjectBase64Invalid,
            ))?;

        from_slice::<Value>(&payload).map_err(AppError::map_source(
            AuthorizeErrorCode::RequestObjectPayloadInvalid,
        ))
    }
}

#[cfg(test)]
pub(in crate::openid_connect::authorize) fn fetchable_request_uri(request_uri: &Url) -> Url {
    fetchable_url(request_uri)
}

fn map_request_uri_fetch_error(error: RemoteFetchError) -> AppError {
    match error {
        RemoteFetchError::NotHttps => AppError::from_code(AuthorizeErrorCode::RequestUriNotHttps),
        RemoteFetchError::UnsafeHost => {
            AppError::from_code(AuthorizeErrorCode::RequestUriUnsafeHost)
        }
        RemoteFetchError::FetchFailed(error) => {
            AppError::from_code(AuthorizeErrorCode::RequestUriFetchFailed).with_source(error)
        }
        RemoteFetchError::ResolveFailed(error) => {
            AppError::from_code(AuthorizeErrorCode::RequestUriUnsafeHost).with_source(error)
        }
        RemoteFetchError::NotOk => AppError::from_code(AuthorizeErrorCode::RequestUriNot200),
        RemoteFetchError::TooLarge => AppError::from_code(AuthorizeErrorCode::RequestUriTooLarge),
        RemoteFetchError::ReadFailed(error) => {
            AppError::from_code(AuthorizeErrorCode::RequestUriReadFailed).with_source(error)
        }
    }
}
