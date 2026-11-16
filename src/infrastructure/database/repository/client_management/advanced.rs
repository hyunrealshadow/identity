//! Advanced OpenID Connect client metadata: projection and column writes.
//!
//! Only columns whose meaning changes are written. Several of these columns
//! participate in the client authorization boundary, so rewriting an equal
//! value in another spelling (`null` versus `false`, a bare host versus a host
//! with `/`) must not look like a change and withdraw issued credentials.

use identity_application::client::{ClientAdvancedSettings, ClientManagementRepositoryError};
use identity_domain::openid_connect::{OpenIdConnectClientMetadata, SubjectType};
use sea_orm::{ActiveModelTrait, DatabaseTransaction, Set};
use serde_json::Value;
use url::Url;

use super::support::{corrupt, storage};
use crate::database::{
    entity::client_openid_connect, repository::openid_connect::mapping::to_metadata,
};

fn names<T: ToString>(values: Option<&Vec<T>>) -> Vec<String> {
    values
        .into_iter()
        .flatten()
        .map(ToString::to_string)
        .collect()
}

fn url(value: Option<&Url>) -> Option<String> {
    value.map(ToString::to_string)
}

/// The administrator-facing view of stored registration metadata. Algorithm
/// lists keep their stored order, which is the runtime's preference order.
pub(super) fn advanced_from_metadata(
    metadata: &OpenIdConnectClientMetadata,
) -> ClientAdvancedSettings {
    ClientAdvancedSettings {
        frontchannel_logout_uri: url(metadata.frontchannel_logout_uri.as_ref()),
        frontchannel_logout_session_required: metadata
            .frontchannel_logout_session_required
            .unwrap_or(false),
        backchannel_logout_uri: url(metadata.backchannel_logout_uri.as_ref()),
        backchannel_logout_session_required: metadata
            .backchannel_logout_session_required
            .unwrap_or(false),
        logo_uri: url(metadata.logo_uri.as_ref()),
        client_uri: url(metadata.client_uri.as_ref()),
        policy_uri: url(metadata.policy_uri.as_ref()),
        tos_uri: url(metadata.tos_uri.as_ref()),
        contacts: metadata.contacts.clone().unwrap_or_default(),
        subject_type: metadata.subject_type.unwrap_or_default(),
        sector_identifier_uri: url(metadata.sector_identifier_uri.as_ref()),
        default_max_age: metadata.default_max_age,
        require_auth_time: metadata.require_auth_time.unwrap_or(false),
        default_acr_values: metadata
            .default_acr_values
            .iter()
            .flatten()
            .map(ToString::to_string)
            .collect(),
        id_token_signed_response_algs: names(metadata.id_token_signed_response_algs.as_ref()),
        id_token_encrypted_response_algs: names(metadata.id_token_encrypted_response_algs.as_ref()),
        id_token_encrypted_response_encs: names(metadata.id_token_encrypted_response_encs.as_ref()),
        userinfo_signed_response_algs: names(metadata.userinfo_signed_response_algs.as_ref()),
        userinfo_encrypted_response_algs: names(metadata.userinfo_encrypted_response_algs.as_ref()),
        userinfo_encrypted_response_encs: names(metadata.userinfo_encrypted_response_encs.as_ref()),
        request_object_signing_algs: names(metadata.request_object_signing_algs.as_ref()),
        request_object_encryption_algs: names(metadata.request_object_encryption_algs.as_ref()),
        request_object_encryption_encs: names(metadata.request_object_encryption_encs.as_ref()),
        request_uris: metadata
            .request_uris
            .iter()
            .flatten()
            .map(ToString::to_string)
            .collect(),
        token_endpoint_auth_signing_algs: names(metadata.token_endpoint_auth_signing_algs.as_ref()),
        initiate_login_uri: url(metadata.initiate_login_uri.as_ref()),
    }
}

/// Spell a URI the way reads return it.
fn canonical_uri(
    value: Option<&String>,
) -> Result<Option<String>, ClientManagementRepositoryError> {
    value
        .map(|raw| {
            Url::parse(raw)
                .map(|url| url.to_string())
                .map_err(|_| corrupt())
        })
        .transpose()
}

fn canonical(
    settings: &ClientAdvancedSettings,
) -> Result<ClientAdvancedSettings, ClientManagementRepositoryError> {
    let mut canonical = settings.clone();
    for value in [
        &mut canonical.frontchannel_logout_uri,
        &mut canonical.backchannel_logout_uri,
        &mut canonical.logo_uri,
        &mut canonical.client_uri,
        &mut canonical.policy_uri,
        &mut canonical.tos_uri,
        &mut canonical.sector_identifier_uri,
        &mut canonical.initiate_login_uri,
    ] {
        *value = canonical_uri(value.as_ref())?;
    }
    canonical.request_uris = settings
        .request_uris
        .iter()
        .map(|raw| canonical_uri(Some(raw)).map(Option::unwrap_or_default))
        .collect::<Result<_, _>>()?;
    Ok(canonical)
}

fn string(value: &Option<String>) -> Option<String> {
    value.clone()
}

fn list(values: &[String]) -> Option<Value> {
    (!values.is_empty()).then(|| Value::Array(values.iter().cloned().map(Value::String).collect()))
}

/// What a write changed that the stored boundary fingerprint cannot see.
pub(super) struct AdvancedChange {
    /// The pairwise sector moved, so every user's `sub` for this client moves.
    pub(super) subject_identity: bool,
}

/// Write the changed advanced metadata columns of one client row.
pub(super) async fn write_advanced(
    txn: &DatabaseTransaction,
    row: client_openid_connect::Model,
    next: &ClientAdvancedSettings,
) -> Result<AdvancedChange, ClientManagementRepositoryError> {
    let current = advanced_from_metadata(&to_metadata(row.clone()).map_err(|_| corrupt())?);
    let next = canonical(next)?;
    if current == next {
        return Ok(AdvancedChange {
            subject_identity: false,
        });
    }
    let mut active: client_openid_connect::ActiveModel = row.into();

    macro_rules! assign {
        ($field:ident, $column:ident, $encode:expr) => {
            if current.$field != next.$field {
                active.$column = Set($encode(&next.$field));
            }
        };
    }
    let flag = |value: &bool| value.then_some(true);
    assign!(frontchannel_logout_uri, frontchannel_logout_uri, string);
    assign!(
        frontchannel_logout_session_required,
        frontchannel_logout_session_required,
        flag
    );
    assign!(backchannel_logout_uri, backchannel_logout_uri, string);
    assign!(
        backchannel_logout_session_required,
        backchannel_logout_session_required,
        flag
    );
    assign!(logo_uri, logo_uri, string);
    assign!(client_uri, client_uri, string);
    assign!(policy_uri, policy_uri, string);
    assign!(tos_uri, tos_uri, string);
    assign!(contacts, contacts, |values: &Vec<String>| list(values));
    assign!(subject_type, subject_type, |value: &SubjectType| {
        (*value != SubjectType::Public).then(|| value.to_string())
    });
    assign!(sector_identifier_uri, sector_identifier_uri, string);
    assign!(default_max_age, default_max_age, |value: &Option<i32>| {
        *value
    });
    assign!(require_auth_time, require_auth_time, flag);
    assign!(default_acr_values, default_acr_values, |values: &Vec<
        String,
    >| list(values));
    assign!(
        id_token_signed_response_algs,
        id_token_signed_response_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        id_token_encrypted_response_algs,
        id_token_encrypted_response_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        id_token_encrypted_response_encs,
        id_token_encrypted_response_encs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        userinfo_signed_response_algs,
        userinfo_signed_response_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        userinfo_encrypted_response_algs,
        userinfo_encrypted_response_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        userinfo_encrypted_response_encs,
        userinfo_encrypted_response_encs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        request_object_signing_algs,
        request_object_signing_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        request_object_encryption_algs,
        request_object_encryption_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(
        request_object_encryption_encs,
        request_object_encryption_encs,
        |values: &Vec<String>| list(values)
    );
    assign!(request_uris, request_uris, |values: &Vec<String>| list(
        values
    ));
    assign!(
        token_endpoint_auth_signing_algs,
        token_endpoint_auth_signing_algs,
        |values: &Vec<String>| list(values)
    );
    assign!(initiate_login_uri, initiate_login_uri, string);
    active.updated_at = Set(Some(chrono::Utc::now().into()));
    active.update(txn).await.map_err(storage)?;

    Ok(AdvancedChange {
        subject_identity: next.subject_type == SubjectType::Pairwise
            && current.sector_identifier_uri != next.sector_identifier_uri,
    })
}
