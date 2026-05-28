use url::Url;

use crate::{
    application::error::{AppError, codes::registration::RegistrationErrorCode},
    domain::openid_connect::{OpenIdConnectClientPlatformType, model::claim::StandardScopes},
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
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if std::env::var("APP_ENV")
        .map(|value| value.eq_ignore_ascii_case("conformance"))
        .unwrap_or(false)
    {
        builder = builder.danger_accept_invalid_certs(true);
    }

    let response = builder
        .build()
        .map_err(|error| {
            AppError::from_code(RegistrationErrorCode::InvalidClientMetadata).with_source(error)
        })?
        .get(sector_identifier_uri.clone())
        .send()
        .await
        .map_err(|error| {
            AppError::from_code(RegistrationErrorCode::InvalidClientMetadata).with_source(error)
        })?;

    if !response.status().is_success() {
        return Err(AppError::from_code(
            RegistrationErrorCode::InvalidClientMetadata,
        ));
    }

    response.json::<Vec<String>>().await.map_err(|error| {
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
