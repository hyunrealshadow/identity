use url::Url;

use crate::{
    application::error::{AppError, codes::registration::RegistrationErrorCode},
    domain::openid_connect::{OpenIdConnectClientPlatformType, model::claim::StandardScopes},
    openid_connect::remote::{
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchPolicy, conformance_allows_invalid_certs,
        fetch_https_public_document, remote_http_client,
    },
};

pub(super) fn parse_application_type(
    value: Option<&str>,
) -> Result<OpenIdConnectClientPlatformType, AppError> {
    let application_type = value.unwrap_or("web");
    application_type.parse().map_err(|error| {
        AppError::from_code(RegistrationErrorCode::UnsupportedApplicationType)
            .with_param("application_type", application_type)
            .with_source(error)
    })
}

pub(super) fn split_scope(value: Option<&str>) -> Vec<String> {
    value.map_or_else(default_scopes, |scope| {
        scope.split_whitespace().map(str::to_owned).collect()
    })
}

pub(super) fn reject_none_outside_conformance(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), AppError> {
    if value == Some("none") && !cfg!(feature = "allow-none-alg") {
        return Err(
            AppError::from_code(RegistrationErrorCode::NoneNotSupported).with_param("field", field)
        );
    }
    Ok(())
}

pub(super) fn validate_initiate_login_uri(value: Option<&Url>) -> Result<(), AppError> {
    let Some(uri) = value else {
        return Ok(());
    };

    if uri.scheme() != "https" {
        return Err(AppError::from_code(
            RegistrationErrorCode::InvalidClientMetadata,
        ));
    }

    Ok(())
}

pub(super) async fn validate_sector_identifier_uri(
    sector_identifier_uri: Option<&Url>,
    redirect_uris: &[Url],
) -> Result<(), AppError> {
    let Some(sector_identifier_uri) = sector_identifier_uri else {
        return Ok(());
    };

    let sector_redirect_uris = fetch_sector_redirect_uris(sector_identifier_uri).await?;
    if sector_redirect_uris_include_registered_redirects(&sector_redirect_uris, redirect_uris) {
        Ok(())
    } else {
        Err(AppError::from_code(
            RegistrationErrorCode::InvalidClientMetadata,
        ))
    }
}

async fn fetch_sector_redirect_uris(sector_identifier_uri: &Url) -> Result<Vec<String>, AppError> {
    let client = remote_http_client(RemoteFetchPolicy::new(
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        std::time::Duration::from_secs(5),
        conformance_allows_invalid_certs(),
    ))
    .map_err(|error| {
        AppError::from_code(RegistrationErrorCode::InvalidClientMetadata).with_source(error)
    })?;

    let body = fetch_https_public_document(
        &client,
        sector_identifier_uri,
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
    )
    .await
    .map_err(|error| {
        AppError::from_code(RegistrationErrorCode::InvalidClientMetadata).with_source(error)
    })?;

    serde_json::from_slice::<Vec<String>>(&body).map_err(|error| {
        AppError::from_code(RegistrationErrorCode::InvalidClientMetadata).with_source(error)
    })
}

pub(crate) fn sector_redirect_uris_include_registered_redirects(
    sector_redirect_uris: &[String],
    redirect_uris: &[Url],
) -> bool {
    redirect_uris.iter().all(|redirect_uri| {
        sector_redirect_uris
            .iter()
            .any(|uri| uri == redirect_uri.as_str())
    })
}

fn default_scopes() -> Vec<String> {
    [
        StandardScopes::OPENID,
        StandardScopes::PROFILE,
        StandardScopes::EMAIL,
        StandardScopes::ADDRESS,
        StandardScopes::PHONE,
        StandardScopes::OFFLINE_ACCESS,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
