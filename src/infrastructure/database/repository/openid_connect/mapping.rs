use crate::database::entity::{client, client_openid_connect, client_openid_connect_platform};
use chrono::Utc;
use identity_domain::{
    client::model::Client,
    openid_connect::{
        OpenIdConnectClientMetadata, OpenIdConnectClientPlatform, OpenIdConnectClientPlatformType,
        OpenIdConnectClientRepositoryError, OpenIdConnectClientSettings,
    },
};
use serde_json::{Value, from_value};
use std::str::FromStr;
use url::Url;

pub(super) fn deserialize_optional_string_vec(
    raw: Option<&Value>,
) -> Result<Option<Vec<String>>, OpenIdConnectClientRepositoryError> {
    raw.cloned()
        .map(from_value::<Vec<String>>)
        .transpose()
        .map_err(OpenIdConnectClientRepositoryError::DeserializeMetadata)
}

pub(super) fn parse_optional_url(
    raw: Option<&str>,
) -> Result<Option<Url>, OpenIdConnectClientRepositoryError> {
    raw.map(Url::parse)
        .transpose()
        .map_err(OpenIdConnectClientRepositoryError::ParseUrl)
}

pub(super) fn parse_optional_urls(
    raw: Option<&Value>,
) -> Result<Option<Vec<Url>>, OpenIdConnectClientRepositoryError> {
    deserialize_optional_string_vec(raw)?
        .map(|values| {
            values
                .into_iter()
                .map(|value| Url::parse(&value))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(OpenIdConnectClientRepositoryError::ParseUrl)
}

fn parse_optional_redirect_uris(
    raw: Option<&Value>,
) -> Result<Vec<String>, OpenIdConnectClientRepositoryError> {
    let values = deserialize_optional_string_vec(raw)?.unwrap_or_default();
    for value in &values {
        Url::parse(value).map_err(OpenIdConnectClientRepositoryError::ParseUrl)?;
    }
    Ok(values)
}

pub(super) fn to_client(
    model: client::Model,
) -> Result<Client, OpenIdConnectClientRepositoryError> {
    Ok(Client {
        oid: model.oid,
        protocol: model
            .protocol
            .parse()
            .map_err(OpenIdConnectClientRepositoryError::ParseClientProtocol)?,
        name: model.name,
        names: deserialize_optional_string_vec(model.names.as_ref())?.unwrap_or_default(),
        description: model.description,
        built_in: model.built_in,
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|v| v.with_timezone(&Utc)),
    })
}

pub(super) fn to_metadata(
    model: client_openid_connect::Model,
) -> Result<OpenIdConnectClientMetadata, OpenIdConnectClientRepositoryError> {
    let settings = from_value::<OpenIdConnectClientSettings>(model.settings)
        .map_err(OpenIdConnectClientRepositoryError::DeserializeMetadata)?;

    Ok(OpenIdConnectClientMetadata {
        post_logout_redirect_uris: parse_optional_urls(model.post_logout_redirect_uris.as_ref())?,
        frontchannel_logout_uri: parse_optional_url(model.frontchannel_logout_uri.as_deref())?,
        frontchannel_logout_session_required: model.frontchannel_logout_session_required,
        backchannel_logout_uri: parse_optional_url(model.backchannel_logout_uri.as_deref())?,
        backchannel_logout_session_required: model.backchannel_logout_session_required,
        response_types: parse_metadata_values(
            "response_types",
            deserialize_optional_string_vec(model.response_types.as_ref())?,
        )?,
        grant_types: parse_metadata_values(
            "grant_types",
            deserialize_optional_string_vec(model.grant_types.as_ref())?,
        )?,
        contacts: deserialize_optional_string_vec(model.contacts.as_ref())?,
        logo_uri: parse_optional_url(model.logo_uri.as_deref())?,
        client_uri: parse_optional_url(model.client_uri.as_deref())?,
        policy_uri: parse_optional_url(model.policy_uri.as_deref())?,
        tos_uri: parse_optional_url(model.tos_uri.as_deref())?,
        sector_identifier_uri: parse_optional_url(model.sector_identifier_uri.as_deref())?,
        subject_type: model
            .subject_type
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(OpenIdConnectClientRepositoryError::ParseSubjectType)?,
        id_token_signed_response_algs: parse_metadata_values(
            "id_token_signed_response_algs",
            deserialize_optional_string_vec(model.id_token_signed_response_algs.as_ref())?,
        )?,
        id_token_encrypted_response_algs: parse_metadata_values(
            "id_token_encrypted_response_algs",
            deserialize_optional_string_vec(model.id_token_encrypted_response_algs.as_ref())?,
        )?,
        id_token_encrypted_response_encs: parse_metadata_values(
            "id_token_encrypted_response_encs",
            deserialize_optional_string_vec(model.id_token_encrypted_response_encs.as_ref())?,
        )?,
        userinfo_signed_response_algs: parse_metadata_values(
            "userinfo_signed_response_algs",
            deserialize_optional_string_vec(model.userinfo_signed_response_algs.as_ref())?,
        )?,
        userinfo_encrypted_response_algs: parse_metadata_values(
            "userinfo_encrypted_response_algs",
            deserialize_optional_string_vec(model.userinfo_encrypted_response_algs.as_ref())?,
        )?,
        userinfo_encrypted_response_encs: parse_metadata_values(
            "userinfo_encrypted_response_encs",
            deserialize_optional_string_vec(model.userinfo_encrypted_response_encs.as_ref())?,
        )?,
        request_object_signing_algs: parse_metadata_values(
            "request_object_signing_algs",
            deserialize_optional_string_vec(model.request_object_signing_algs.as_ref())?,
        )?,
        request_object_encryption_algs: parse_metadata_values(
            "request_object_encryption_algs",
            deserialize_optional_string_vec(model.request_object_encryption_algs.as_ref())?,
        )?,
        request_object_encryption_encs: parse_metadata_values(
            "request_object_encryption_encs",
            deserialize_optional_string_vec(model.request_object_encryption_encs.as_ref())?,
        )?,
        token_endpoint_auth_methods: parse_metadata_values(
            "token_endpoint_auth_methods",
            deserialize_optional_string_vec(model.token_endpoint_auth_methods.as_ref())?,
        )?,
        token_endpoint_auth_signing_algs: parse_metadata_values(
            "token_endpoint_auth_signing_algs",
            deserialize_optional_string_vec(model.token_endpoint_auth_signing_algs.as_ref())?,
        )?,
        default_max_age: model.default_max_age,
        require_auth_time: model.require_auth_time,
        default_acr_values: deserialize_optional_string_vec(model.default_acr_values.as_ref())?,
        initiate_login_uri: parse_optional_url(model.initiate_login_uri.as_deref())?,
        request_uris: parse_optional_urls(model.request_uris.as_ref())?,
        settings,
    })
}

fn parse_metadata_values<T: FromStr>(
    field: &'static str,
    values: Option<Vec<String>>,
) -> Result<Option<Vec<T>>, OpenIdConnectClientRepositoryError> {
    values
        .map(|values| {
            values
                .into_iter()
                .map(|value| {
                    value.parse().map_err(|_| {
                        OpenIdConnectClientRepositoryError::InvalidMetadataValue { field, value }
                    })
                })
                .collect()
        })
        .transpose()
}

pub(super) fn to_platform(
    model: client_openid_connect_platform::Model,
) -> Result<OpenIdConnectClientPlatform, OpenIdConnectClientRepositoryError> {
    Ok(OpenIdConnectClientPlatform {
        platform: model
            .platform
            .parse::<OpenIdConnectClientPlatformType>()
            .map_err(OpenIdConnectClientRepositoryError::ParseClientPlatform)?,
        redirect_uris: parse_optional_redirect_uris(model.redirect_uris.as_ref())?,
    })
}
