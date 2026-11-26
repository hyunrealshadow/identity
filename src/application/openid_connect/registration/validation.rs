use std::{str::FromStr, time::Duration};

use serde_json::from_slice;
use url::Url;

use crate::{
    application::error::{AppError, codes::registration},
    domain::{
        key::JwaSigningAlgorithm,
        openid_connect::{
            GrantType, OpenIdConnectClientPlatformType, ResponseType, model::claim::StandardScopes,
        },
    },
    openid_connect::{
        jose::{
            REQUEST_OBJECT_CONTENT_ENCRYPTION_ALGORITHMS, REQUEST_OBJECT_ENCRYPTION_ALGORITHMS,
        },
        remote::{
            DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
            fetch_https_public_document, remote_http_client,
        },
    },
};

pub(super) fn parse_metadata_value<T: FromStr>(
    _field: &'static str,
    value: Option<&str>,
) -> Result<Option<T>, AppError> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| registration::error::InvalidClientMetadata.into_error())
        })
        .transpose()
}

pub(super) fn parse_metadata_values<T: FromStr>(
    _field: &'static str,
    values: Option<&[String]>,
) -> Result<Option<Vec<T>>, AppError> {
    values
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| registration::error::InvalidClientMetadata.into_error())
                })
                .collect()
        })
        .transpose()
}

/// RFC 7591 §2 / OIDC Registration §2 default: the code flow only.
pub(super) fn default_response_types() -> Vec<ResponseType> {
    vec![ResponseType::Code]
}

/// Every registered response type must be backed by the grants it uses:
/// `code` needs `authorization_code`, implicit and hybrid response types need
/// `implicit` (hybrid needs both). Inconsistent registrations are rejected so a
/// client cannot register a response type whose grant it never allows.
pub(super) fn validate_grant_response_type_consistency(
    response_types: &[ResponseType],
    grant_types: &[GrantType],
) -> Result<(), AppError> {
    let inconsistent = response_types.iter().any(|response_type| {
        response_type
            .required_grants()
            .iter()
            .any(|grant| !grant_types.contains(grant))
    });

    if inconsistent {
        return Err(registration::error::InvalidClientMetadata.into_error());
    }

    Ok(())
}

pub(super) fn parse_application_type(
    value: Option<&str>,
) -> Result<OpenIdConnectClientPlatformType, AppError> {
    let application_type = value.unwrap_or("web");
    application_type.parse().map_err(|error| {
        registration::error::UnsupportedApplicationType::new(application_type).with_source(error)
    })
}

pub(super) fn split_scope(value: Option<&str>) -> Vec<String> {
    value.map_or_else(default_scopes, |scope| {
        scope.split_whitespace().map(str::to_owned).collect()
    })
}

pub(super) fn reject_none_algorithm(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), AppError> {
    if value == Some("none") && !cfg!(feature = "allow-none-alg") {
        return Err(registration::error::NoneNotSupported::new(field).into_error());
    }
    Ok(())
}

pub(super) fn validate_response_signing_algorithm(
    _field: &'static str,
    value: Option<&str>,
    allow_none: bool,
) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.parse::<JwaSigningAlgorithm>().is_ok()
        || (allow_none && value == "none" && cfg!(feature = "allow-none-alg"))
    {
        return Ok(());
    }
    Err(registration::error::InvalidClientMetadata.into_error())
}

pub(super) fn validate_response_encryption_algorithm(
    _field: &'static str,
    value: Option<&str>,
) -> Result<(), AppError> {
    if value.is_some_and(|value| {
        !matches!(
            value,
            "RSA-OAEP" | "RSA-OAEP-256" | "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A256KW"
        )
    }) {
        return Err(registration::error::InvalidClientMetadata.into_error());
    }
    Ok(())
}

pub(super) fn validate_request_object_encryption(
    alg: Option<&str>,
    enc: Option<&str>,
) -> Result<(), AppError> {
    let invalid_field = alg
        .filter(|value| !REQUEST_OBJECT_ENCRYPTION_ALGORITHMS.contains(value))
        .map(|_| "request_object_encryption_alg")
        .or_else(|| {
            enc.filter(|value| !REQUEST_OBJECT_CONTENT_ENCRYPTION_ALGORITHMS.contains(value))
                .map(|_| "request_object_encryption_enc")
        })
        .or_else(|| (enc.is_some() && alg.is_none()).then_some("request_object_encryption_alg"));

    if invalid_field.is_some() {
        return Err(registration::error::InvalidClientMetadata.into_error());
    }

    Ok(())
}

pub(super) fn validate_request_object_signing(value: Option<&str>) -> Result<(), AppError> {
    if value.is_some_and(|value| value != "none" && value.parse::<JwaSigningAlgorithm>().is_err()) {
        return Err(registration::error::InvalidClientMetadata.into_error());
    }

    Ok(())
}

pub(super) fn validate_initiate_login_uri(value: Option<&Url>) -> Result<(), AppError> {
    let Some(uri) = value else {
        return Ok(());
    };

    if uri.scheme() != "https" {
        return Err(registration::error::InvalidClientMetadata.into_error());
    }

    Ok(())
}

pub(super) async fn validate_sector_identifier_uri(
    sector_identifier_uri: Option<&Url>,
    redirect_uris: &[String],
) -> Result<(), AppError> {
    let Some(sector_identifier_uri) = sector_identifier_uri else {
        return Ok(());
    };

    let sector_redirect_uris = fetch_sector_redirect_uris(sector_identifier_uri).await?;
    if sector_redirect_uris_include_registered_redirects(&sector_redirect_uris, redirect_uris) {
        Ok(())
    } else {
        Err(registration::error::InvalidClientMetadata.into_error())
    }
}

/// Load a sector identifier document: a JSON array of redirect URIs served
/// over public HTTPS.
pub(crate) async fn fetch_sector_redirect_uris(
    sector_identifier_uri: &Url,
) -> Result<Vec<String>, AppError> {
    let client = remote_http_client(RemoteFetchPolicy::new(
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        Duration::from_secs(5),
        conformance_allows_invalid_certs(),
    ))
    .map_err(registration::error::InvalidClientMetadata::map_source())?;

    let body = fetch_https_public_document(
        &client,
        sector_identifier_uri,
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
    )
    .await
    .map_err(registration::error::InvalidClientMetadata::map_source())?;

    from_slice::<Vec<String>>(&body)
        .map_err(registration::error::InvalidClientMetadata::map_source())
}

pub(crate) fn sector_redirect_uris_include_registered_redirects(
    sector_redirect_uris: &[String],
    redirect_uris: &[String],
) -> bool {
    redirect_uris
        .iter()
        .all(|redirect_uri| sector_redirect_uris.iter().any(|uri| uri == redirect_uri))
}

fn default_scopes() -> Vec<String> {
    #[cfg(feature = "oidc-conformance")]
    return vec![
        StandardScopes::OPENID.to_owned(),
        StandardScopes::PROFILE.to_owned(),
        StandardScopes::EMAIL.to_owned(),
        StandardScopes::ADDRESS.to_owned(),
        StandardScopes::PHONE.to_owned(),
        StandardScopes::OFFLINE_ACCESS.to_owned(),
    ];

    #[cfg(not(feature = "oidc-conformance"))]
    vec![StandardScopes::OPENID.to_owned()]
}
