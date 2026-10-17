use super::{query_error, query_failed};
use crate::database::entity::client_authorization;
use chrono::Utc;
use identity_domain::{
    client::model::ClientOid,
    client_authorization::{
        AccessTokenData, AuthorizationCodeData, ClientAuthorization, ClientAuthorizationData,
        ClientAuthorizationRepositoryError, ClientAuthorizationType, DeviceAuthorizationData,
        DeviceAuthorizationRequestData, PushedAuthorizationRequestData, RefreshTokenData,
        RegistrationAccessTokenData, StoredAuthorizationRequest,
    },
    openid_connect::AuthorizationRequestData,
};
use sea_orm::DbErr;
use serde_json::{Value, from_value, to_value};
pub(super) fn parse_stored_authorization_request(
    data: Value,
) -> Result<StoredAuthorizationRequest, ClientAuthorizationRepositoryError> {
    from_value::<StoredAuthorizationRequest>(data.clone())
        .or_else(|_| {
            from_value::<AuthorizationRequestData>(data).map(|request| StoredAuthorizationRequest {
                request,
                interaction: Default::default(),
            })
        })
        .map_err(|_| {
            query_failed(
                "client_authorization.parse_stored_authorization_request",
                DbErr::Type("invalid authorization_request payload".into()),
            )
        })
}

pub(in super::super) fn serialize_data(
    data: &ClientAuthorizationData,
) -> Result<Value, ClientAuthorizationRepositoryError> {
    match data {
        ClientAuthorizationData::PushedAuthorizationRequest(value) => to_value(value),
        ClientAuthorizationData::AuthorizationRequest(value) => to_value(value),
        ClientAuthorizationData::AuthorizationCode(value) => to_value(value),
        ClientAuthorizationData::AccessToken(value) => to_value(value),
        ClientAuthorizationData::RefreshToken(value) => to_value(value),
        ClientAuthorizationData::RegistrationAccessToken(value) => to_value(value),
        ClientAuthorizationData::DeviceAuthorizationRequest(value) => to_value(value),
        ClientAuthorizationData::DeviceAuthorization(value) => to_value(value),
    }
    .map_err(query_error("client_authorization.serialize_data"))
}

fn parse_data(
    type_: &ClientAuthorizationType,
    data: Value,
) -> Result<ClientAuthorizationData, ClientAuthorizationRepositoryError> {
    match type_ {
        ClientAuthorizationType::PushedAuthorizationRequest => {
            from_value::<PushedAuthorizationRequestData>(data)
                .map(ClientAuthorizationData::PushedAuthorizationRequest)
        }
        ClientAuthorizationType::AuthorizationRequest => {
            return parse_stored_authorization_request(data)
                .map(ClientAuthorizationData::AuthorizationRequest);
        }
        ClientAuthorizationType::AuthorizationCode => from_value::<AuthorizationCodeData>(data)
            .map(ClientAuthorizationData::AuthorizationCode),
        ClientAuthorizationType::AccessToken => {
            from_value::<AccessTokenData>(data).map(ClientAuthorizationData::AccessToken)
        }
        ClientAuthorizationType::RefreshToken => {
            from_value::<RefreshTokenData>(data).map(ClientAuthorizationData::RefreshToken)
        }
        ClientAuthorizationType::RegistrationAccessToken => {
            from_value::<RegistrationAccessTokenData>(data)
                .map(ClientAuthorizationData::RegistrationAccessToken)
        }
        ClientAuthorizationType::DeviceAuthorizationRequest => {
            from_value::<DeviceAuthorizationRequestData>(data)
                .map(ClientAuthorizationData::DeviceAuthorizationRequest)
        }
        ClientAuthorizationType::DeviceAuthorization => from_value::<DeviceAuthorizationData>(data)
            .map(ClientAuthorizationData::DeviceAuthorization),
    }
    .map_err(query_error("client_authorization.parse_data"))
}

pub(in super::super) fn to_domain(
    model: client_authorization::Model,
    client_oid: ClientOid,
) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
    let type_ = model
        .r#type
        .parse::<ClientAuthorizationType>()
        .map_err(|_| {
            query_failed(
                "client_authorization.to_domain",
                DbErr::Type("invalid client_authorization.type".into()),
            )
        })?;
    let data = parse_data(&type_, model.data)?;

    Ok(ClientAuthorization {
        oid: model.oid,
        client_oid,
        type_,
        data,
        expires_at: model.expires_at.with_timezone(&Utc),
        completed_at: model.completed_at.map(|value| value.with_timezone(&Utc)),
        revoked_at: model.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|value| value.with_timezone(&Utc)),
    })
}
