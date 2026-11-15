//! Validation for the advanced OpenID Connect client metadata.
//!
//! Supported values come from the provider's live options, the same lists
//! discovery publishes, so an administrator can choose only what this
//! instance honours now. A value the client already holds stays acceptable
//! after its key is retired, so unrelated edits are not blocked; the
//! administrator removes it explicitly.

use identity_domain::openid_connect::{OpenIdConnectClientPlatformType, SubjectType};
use url::Url;

use super::super::model::{
    ClientAdvancedSettings, MAX_ALGORITHMS, MAX_CONTACT_LENGTH, MAX_CONTACTS,
    MAX_DEFAULT_ACR_VALUES, MAX_DEFAULT_MAX_AGE_SECONDS, MAX_REQUEST_URIS, MAX_URI_LENGTH,
};
use crate::{
    error::{AppError, codes::client::ClientErrorCode},
    openid_connect::{
        provider::ClientMetadataOptions,
        registration::{
            fetch_sector_redirect_uris, sector_redirect_uris_include_registered_redirects,
        },
    },
};

const PREFIX: &str = "advancedSettings";

fn field(name: &str) -> String {
    format!("{PREFIX}.{name}")
}

fn trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// HTTPS, or HTTP on `localhost` for local development, as for Web redirects.
fn web_uri(url: &Url) -> bool {
    OpenIdConnectClientPlatformType::Web.allows_redirect_uri_scheme(url)
}

fn https_uri(url: &Url) -> bool {
    url.scheme() == "https"
}

fn uri(
    value: Option<String>,
    name: &'static str,
    allowed: fn(&Url) -> bool,
) -> Result<Option<String>, AppError> {
    let Some(value) = trimmed(value) else {
        return Ok(None);
    };
    let invalid = || {
        AppError::from_code(ClientErrorCode::InvalidMetadataUri)
            .with_param("uri", value.clone())
            .with_field(field(name))
    };
    if value.len() > MAX_URI_LENGTH {
        return Err(invalid());
    }
    let url = Url::parse(&value).map_err(|_| invalid())?;
    if url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !allowed(&url)
    {
        return Err(invalid());
    }
    Ok(Some(value))
}

fn bounded_list(
    values: Vec<String>,
    max: usize,
    name: &'static str,
) -> Result<Vec<String>, AppError> {
    let mut unique = Vec::new();
    for value in values.into_iter().filter_map(|value| trimmed(Some(value))) {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    if unique.len() > max {
        return Err(AppError::from_code(ClientErrorCode::InvalidCollectionSize)
            .with_param("max", max.to_string())
            .with_field(field(name)));
    }
    Ok(unique)
}

fn unsupported(value: &str, name: &'static str) -> AppError {
    AppError::from_code(ClientErrorCode::UnsupportedAlgorithm)
        .with_param("algorithm", value.to_owned())
        .with_field(field(name))
}

/// Supported values for this purpose, or values the client already holds,
/// deduplicated in the submitted order (the runtime's order of preference).
fn listed(
    values: Vec<String>,
    supported: &[String],
    current: &[String],
    name: &'static str,
) -> Result<Vec<String>, AppError> {
    let values = bounded_list(values, MAX_ALGORITHMS, name)?;
    if let Some(value) = values
        .iter()
        .find(|value| !supported.contains(value) && !current.contains(value))
    {
        return Err(unsupported(value, name));
    }
    Ok(values)
}

#[allow(clippy::too_many_arguments)]
fn encryption_pair(
    algs: Vec<String>,
    encs: Vec<String>,
    supported_alg: &[String],
    supported_enc: &[String],
    current_alg: &[String],
    current_enc: &[String],
    alg_name: &'static str,
    enc_name: &'static str,
) -> Result<(Vec<String>, Vec<String>), AppError> {
    let algs = listed(algs, supported_alg, current_alg, alg_name)?;
    let encs = listed(encs, supported_enc, current_enc, enc_name)?;
    if !encs.is_empty() && algs.is_empty() {
        return Err(
            AppError::from_code(ClientErrorCode::EncryptionAlgorithmRequired)
                .with_field(field(alg_name)),
        );
    }
    Ok((algs, encs))
}

/// Normalize and check everything that does not need the client's redirect
/// URIs or a network fetch.
pub(crate) fn validate_advanced_settings(
    settings: ClientAdvancedSettings,
    options: &ClientMetadataOptions,
    current: &ClientAdvancedSettings,
) -> Result<ClientAdvancedSettings, AppError> {
    let frontchannel_logout_uri = uri(
        settings.frontchannel_logout_uri,
        "frontchannelLogoutUri",
        web_uri,
    )?;
    let backchannel_logout_uri = uri(
        settings.backchannel_logout_uri,
        "backchannelLogoutUri",
        web_uri,
    )?;
    if settings.frontchannel_logout_session_required && frontchannel_logout_uri.is_none() {
        return Err(AppError::from_code(ClientErrorCode::LogoutUriRequired)
            .with_field(field("frontchannelLogoutUri")));
    }
    if settings.backchannel_logout_session_required && backchannel_logout_uri.is_none() {
        return Err(AppError::from_code(ClientErrorCode::LogoutUriRequired)
            .with_field(field("backchannelLogoutUri")));
    }

    let mut contacts = Vec::new();
    for contact in bounded_list(settings.contacts, MAX_CONTACTS, "contacts")? {
        if contact.chars().count() > MAX_CONTACT_LENGTH {
            return Err(AppError::from_code(ClientErrorCode::InvalidContact)
                .with_param("max", MAX_CONTACT_LENGTH.to_string())
                .with_field(field("contacts")));
        }
        contacts.push(contact);
    }

    if settings
        .default_max_age
        .is_some_and(|age| !(0..=MAX_DEFAULT_MAX_AGE_SECONDS).contains(&age))
    {
        return Err(AppError::from_code(ClientErrorCode::InvalidDefaultMaxAge)
            .with_param("max", MAX_DEFAULT_MAX_AGE_SECONDS.to_string())
            .with_field(field("defaultMaxAge")));
    }

    let default_acr_values = bounded_list(
        settings.default_acr_values,
        MAX_DEFAULT_ACR_VALUES,
        "defaultAcrValues",
    )?;
    if let Some(acr) = default_acr_values
        .iter()
        .find(|acr| !options.acr_values.contains(acr) && !current.default_acr_values.contains(acr))
    {
        return Err(AppError::from_code(ClientErrorCode::UnsupportedAcrValue)
            .with_param("acr", acr.clone())
            .with_field(field("defaultAcrValues")));
    }

    let (id_token_encrypted_response_algs, id_token_encrypted_response_encs) = encryption_pair(
        settings.id_token_encrypted_response_algs,
        settings.id_token_encrypted_response_encs,
        &options.id_token_encryption_algs,
        &options.id_token_encryption_encs,
        &current.id_token_encrypted_response_algs,
        &current.id_token_encrypted_response_encs,
        "idTokenEncryptedResponseAlgs",
        "idTokenEncryptedResponseEncs",
    )?;
    let (userinfo_encrypted_response_algs, userinfo_encrypted_response_encs) = encryption_pair(
        settings.userinfo_encrypted_response_algs,
        settings.userinfo_encrypted_response_encs,
        &options.userinfo_encryption_algs,
        &options.userinfo_encryption_encs,
        &current.userinfo_encrypted_response_algs,
        &current.userinfo_encrypted_response_encs,
        "userinfoEncryptedResponseAlgs",
        "userinfoEncryptedResponseEncs",
    )?;
    let (request_object_encryption_algs, request_object_encryption_encs) = encryption_pair(
        settings.request_object_encryption_algs,
        settings.request_object_encryption_encs,
        &options.request_object_encryption_algs,
        &options.request_object_encryption_encs,
        &current.request_object_encryption_algs,
        &current.request_object_encryption_encs,
        "requestObjectEncryptionAlgs",
        "requestObjectEncryptionEncs",
    )?;

    let mut request_uris = Vec::new();
    for raw in bounded_list(settings.request_uris, MAX_REQUEST_URIS, "requestUris")? {
        if let Some(value) = uri(Some(raw), "requestUris", web_uri)? {
            request_uris.push(value);
        }
    }

    Ok(ClientAdvancedSettings {
        frontchannel_logout_session_required: settings.frontchannel_logout_session_required,
        frontchannel_logout_uri,
        backchannel_logout_session_required: settings.backchannel_logout_session_required,
        backchannel_logout_uri,
        logo_uri: uri(settings.logo_uri, "logoUri", web_uri)?,
        client_uri: uri(settings.client_uri, "clientUri", web_uri)?,
        policy_uri: uri(settings.policy_uri, "policyUri", web_uri)?,
        tos_uri: uri(settings.tos_uri, "tosUri", web_uri)?,
        contacts,
        subject_type: settings.subject_type,
        sector_identifier_uri: uri(
            settings.sector_identifier_uri,
            "sectorIdentifierUri",
            https_uri,
        )?,
        default_max_age: settings.default_max_age,
        require_auth_time: settings.require_auth_time,
        default_acr_values,
        id_token_signed_response_algs: listed(
            settings.id_token_signed_response_algs,
            &options.id_token_signing_algs,
            &current.id_token_signed_response_algs,
            "idTokenSignedResponseAlgs",
        )?,
        id_token_encrypted_response_algs,
        id_token_encrypted_response_encs,
        userinfo_signed_response_algs: listed(
            settings.userinfo_signed_response_algs,
            &options.userinfo_signing_algs,
            &current.userinfo_signed_response_algs,
            "userinfoSignedResponseAlgs",
        )?,
        userinfo_encrypted_response_algs,
        userinfo_encrypted_response_encs,
        request_object_signing_algs: listed(
            settings.request_object_signing_algs,
            &options.request_object_signing_algs,
            &current.request_object_signing_algs,
            "requestObjectSigningAlgs",
        )?,
        request_object_encryption_algs,
        request_object_encryption_encs,
        request_uris,
        token_endpoint_auth_signing_algs: listed(
            settings.token_endpoint_auth_signing_algs,
            &options.token_endpoint_auth_signing_algs,
            &current.token_endpoint_auth_signing_algs,
            "tokenEndpointAuthSigningAlgs",
        )?,
        initiate_login_uri: uri(settings.initiate_login_uri, "initiateLoginUri", https_uri)?,
    })
}

fn redirect_hosts(redirect_uris: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for host in redirect_uris
        .iter()
        .filter_map(|raw| Url::parse(raw).ok())
        .filter_map(|url| url.host_str().map(str::to_owned))
    {
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// Pairwise subjects with redirect URIs on several hosts need a sector
/// identifier (OpenID Connect Core §8.1), and a registered sector document must
/// list every redirect URI.
pub(crate) async fn validate_subject_identifier(
    settings: &ClientAdvancedSettings,
    redirect_uris: &[String],
) -> Result<(), AppError> {
    let Some(sector) = settings.sector_identifier_uri.as_deref() else {
        if settings.subject_type == SubjectType::Pairwise && redirect_hosts(redirect_uris).len() > 1
        {
            return Err(
                AppError::from_code(ClientErrorCode::SectorIdentifierRequired)
                    .with_field(field("sectorIdentifierUri")),
            );
        }
        return Ok(());
    };
    let sector = Url::parse(sector).map_err(|_| {
        AppError::from_code(ClientErrorCode::InvalidMetadataUri)
            .with_param("uri", sector.to_owned())
            .with_field(field("sectorIdentifierUri"))
    })?;
    let listed = fetch_sector_redirect_uris(&sector).await.map_err(|error| {
        AppError::from_code(ClientErrorCode::SectorIdentifierUnavailable)
            .with_field(field("sectorIdentifierUri"))
            .with_source(error)
    })?;
    if sector_redirect_uris_include_registered_redirects(&listed, redirect_uris) {
        Ok(())
    } else {
        Err(
            AppError::from_code(ClientErrorCode::SectorIdentifierMismatch)
                .with_field(field("sectorIdentifierUri")),
        )
    }
}

#[cfg(test)]
mod tests {
    use identity_domain::openid_connect::SubjectType;

    use super::{validate_advanced_settings, validate_subject_identifier};
    use crate::{
        client::model::ClientAdvancedSettings,
        error::{AppError, code::AppErrorCode, codes::client::ClientErrorCode},
        openid_connect::provider::ClientMetadataOptions,
    };

    /// What a provider with one ES256 and one PS256 signing key and an RSA
    /// encryption key would offer.
    fn options() -> ClientMetadataOptions {
        let names = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
        ClientMetadataOptions {
            subject_types: names(&["public", "pairwise"]),
            acr_values: names(&["aal1", "aal2"]),
            id_token_signing_algs: names(&["ES256", "PS256"]),
            id_token_encryption_algs: names(&["RSA-OAEP", "RSA-OAEP-256", "ECDH-ES"]),
            id_token_encryption_encs: names(&["A128CBC-HS256", "A256GCM"]),
            userinfo_signing_algs: names(&["ES256", "PS256"]),
            userinfo_encryption_algs: names(&["RSA-OAEP", "RSA-OAEP-256"]),
            userinfo_encryption_encs: names(&["A128CBC-HS256"]),
            request_object_signing_algs: names(&["none", "ES256", "RS256"]),
            request_object_encryption_algs: names(&["RSA-OAEP-256"]),
            request_object_encryption_encs: names(&["A128CBC-HS256"]),
            token_endpoint_auth_signing_algs: names(&["HS256", "ES256", "RS256"]),
        }
    }

    fn validate(settings: ClientAdvancedSettings) -> Result<ClientAdvancedSettings, AppError> {
        validate_advanced_settings(settings, &options(), &ClientAdvancedSettings::default())
    }

    fn rejected(settings: ClientAdvancedSettings) -> u32 {
        validate(settings).unwrap_err().code()
    }

    #[test]
    fn normalizes_blank_values_to_provider_defaults() {
        let settings = validate(ClientAdvancedSettings {
            logo_uri: Some("  ".into()),
            id_token_signed_response_algs: vec![" ".into(), "ES256".into(), "ES256".into()],
            contacts: vec![
                " ops@example.com ".into(),
                "ops@example.com".into(),
                "".into(),
            ],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(settings.logo_uri, None);
        assert_eq!(settings.id_token_signed_response_algs, ["ES256"]);
        assert_eq!(settings.contacts, ["ops@example.com"]);
    }

    #[test]
    fn rejects_response_signing_without_a_key_algorithm() {
        // RS256 is a valid JOSE name, but no active key signs with it.
        for alg in ["none", "HS256", "RS256", "nonsense"] {
            assert_eq!(
                rejected(ClientAdvancedSettings {
                    id_token_signed_response_algs: vec!["ES256".into(), alg.into()],
                    ..Default::default()
                }),
                ClientErrorCode::UnsupportedAlgorithm.code(),
                "{alg}"
            );
        }
        validate(ClientAdvancedSettings {
            id_token_signed_response_algs: vec!["PS256".into(), "ES256".into()],
            userinfo_signed_response_algs: vec!["ES256".into()],
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn content_encryption_needs_a_key_management_algorithm() {
        assert_eq!(
            rejected(ClientAdvancedSettings {
                id_token_encrypted_response_encs: vec!["A256GCM".into()],
                ..Default::default()
            }),
            ClientErrorCode::EncryptionAlgorithmRequired.code()
        );
        assert_eq!(
            rejected(ClientAdvancedSettings {
                userinfo_encrypted_response_algs: vec!["RSA-OAEP".into(), "ECDH-ES".into()],
                ..Default::default()
            }),
            ClientErrorCode::UnsupportedAlgorithm.code()
        );
        validate(ClientAdvancedSettings {
            id_token_encrypted_response_algs: vec!["RSA-OAEP-256".into(), "ECDH-ES".into()],
            id_token_encrypted_response_encs: vec!["A256GCM".into(), "A128CBC-HS256".into()],
            ..Default::default()
        })
        .unwrap();
        // No active key decrypts ECDH-ES request objects.
        assert_eq!(
            rejected(ClientAdvancedSettings {
                request_object_encryption_algs: vec!["ECDH-ES".into()],
                ..Default::default()
            }),
            ClientErrorCode::UnsupportedAlgorithm.code()
        );
    }

    #[test]
    fn keeps_a_stored_algorithm_after_its_key_is_retired() {
        let current = ClientAdvancedSettings {
            id_token_signed_response_algs: vec!["RS256".into()],
            ..Default::default()
        };
        let kept = validate_advanced_settings(
            ClientAdvancedSettings {
                logo_uri: Some("https://cdn.example.com/logo.png".into()),
                ..current.clone()
            },
            &options(),
            &current,
        )
        .unwrap();
        assert_eq!(kept.id_token_signed_response_algs, ["RS256"]);
        // Adding another unavailable value is still rejected.
        assert!(
            validate_advanced_settings(
                ClientAdvancedSettings {
                    id_token_signed_response_algs: vec!["RS256".into(), "RS384".into()],
                    ..Default::default()
                },
                &options(),
                &current,
            )
            .is_err()
        );
    }

    #[test]
    fn session_requirement_needs_its_logout_uri() {
        assert_eq!(
            rejected(ClientAdvancedSettings {
                backchannel_logout_session_required: true,
                ..Default::default()
            }),
            ClientErrorCode::LogoutUriRequired.code()
        );
    }

    #[test]
    fn rejects_unsafe_uris_and_out_of_range_values() {
        for settings in [
            ClientAdvancedSettings {
                logo_uri: Some("http://cdn.example.com/logo.png".into()),
                ..Default::default()
            },
            ClientAdvancedSettings {
                initiate_login_uri: Some("http://localhost/login".into()),
                ..Default::default()
            },
            ClientAdvancedSettings {
                policy_uri: Some("https://user:pass@example.com/policy".into()),
                ..Default::default()
            },
        ] {
            assert_eq!(
                rejected(settings),
                ClientErrorCode::InvalidMetadataUri.code()
            );
        }
        assert_eq!(
            rejected(ClientAdvancedSettings {
                default_max_age: Some(-1),
                ..Default::default()
            }),
            ClientErrorCode::InvalidDefaultMaxAge.code()
        );
        assert_eq!(
            rejected(ClientAdvancedSettings {
                default_acr_values: vec!["urn:example:unknown".into()],
                ..Default::default()
            }),
            ClientErrorCode::UnsupportedAcrValue.code()
        );
        assert_eq!(
            rejected(ClientAdvancedSettings {
                token_endpoint_auth_signing_algs: vec!["none".into()],
                ..Default::default()
            }),
            ClientErrorCode::UnsupportedAlgorithm.code()
        );
    }

    #[tokio::test]
    async fn pairwise_across_hosts_requires_a_sector_identifier() {
        let pairwise = ClientAdvancedSettings {
            subject_type: SubjectType::Pairwise,
            ..Default::default()
        };
        let one_host = [
            "https://a.example.com/cb".to_owned(),
            "https://a.example.com/2".to_owned(),
        ];
        validate_subject_identifier(&pairwise, &one_host)
            .await
            .unwrap();
        let two_hosts = [
            "https://a.example.com/cb".to_owned(),
            "https://b.example.com/cb".to_owned(),
        ];
        assert_eq!(
            validate_subject_identifier(&pairwise, &two_hosts)
                .await
                .unwrap_err()
                .code(),
            ClientErrorCode::SectorIdentifierRequired.code()
        );
        validate_subject_identifier(&ClientAdvancedSettings::default(), &two_hosts)
            .await
            .unwrap();
    }
}
