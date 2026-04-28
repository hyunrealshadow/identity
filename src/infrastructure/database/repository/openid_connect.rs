use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use serde_json::Value;
use url::Url;

use crate::domain::client::model::Client;
use crate::domain::openid_connect::{
    OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
    OpenIdConnectClientPlatformType, OpenIdConnectClientRepository,
    OpenIdConnectClientRepositoryError, OpenIdConnectClientSettings,
};
use crate::infrastructure::database::entity::{
    client, client::Entity as ClientEntity, client_open_id_connect,
    client_open_id_connect::Entity as OpenIdConnectClientEntity, client_platform,
    client_platform::Entity as ClientPlatformEntity, client_scope,
    client_scope::Entity as ClientScopeEntity, scope, scope::Entity as ScopeEntity,
};

fn deserialize_optional_string_vec(
    raw: Option<&Value>,
) -> Result<Option<Vec<String>>, OpenIdConnectClientRepositoryError> {
    raw.cloned()
        .map(serde_json::from_value::<Vec<String>>)
        .transpose()
        .map_err(OpenIdConnectClientRepositoryError::DeserializeMetadata)
}

fn parse_optional_url(
    raw: Option<&str>,
) -> Result<Option<Url>, OpenIdConnectClientRepositoryError> {
    raw.map(Url::parse)
        .transpose()
        .map_err(OpenIdConnectClientRepositoryError::ParseUrl)
}

fn parse_optional_urls(
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

fn to_client(model: client::Model) -> Result<Client, OpenIdConnectClientRepositoryError> {
    Ok(Client {
        oid: model.oid,
        protocol: model
            .protocol
            .parse()
            .map_err(OpenIdConnectClientRepositoryError::ParseClientProtocol)?,
        name: model.name,
        names: deserialize_optional_string_vec(model.names.as_ref())?.unwrap_or_default(),
        description: model.description,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(model.created_at, Utc),
        updated_at: model
            .updated_at
            .map(|v| DateTime::<Utc>::from_naive_utc_and_offset(v, Utc)),
    })
}

fn to_metadata(
    model: client_open_id_connect::Model,
) -> Result<OpenIdConnectClientMetadata, OpenIdConnectClientRepositoryError> {
    let settings = serde_json::from_value::<OpenIdConnectClientSettings>(model.settings)
        .map_err(OpenIdConnectClientRepositoryError::DeserializeMetadata)?;

    Ok(OpenIdConnectClientMetadata {
        post_logout_redirect_uris: parse_optional_urls(model.post_logout_redirect_uris.as_ref())?,
        response_types: deserialize_optional_string_vec(model.response_types.as_ref())?,
        grant_types: deserialize_optional_string_vec(model.grant_types.as_ref())?,
        contacts: deserialize_optional_string_vec(model.contacts.as_ref())?,
        logo_uri: parse_optional_url(model.logo_uri.as_deref())?,
        client_uri: parse_optional_url(model.client_uri.as_deref())?,
        policy_uri: parse_optional_url(model.policy_uri.as_deref())?,
        tos_uri: parse_optional_url(model.tos_uri.as_deref())?,
        sector_identifier_uri: parse_optional_url(model.sector_identifier_uri.as_deref())?,
        subject_type: model.subject_type,
        id_token_signed_response_alg: model.id_token_signed_response_alg,
        id_token_encrypted_response_alg: model.id_token_encrypted_response_alg,
        id_token_encrypted_response_enc: model.id_token_encrypted_response_enc,
        userinfo_signed_response_alg: model.userinfo_signed_response_alg,
        userinfo_encrypted_response_alg: model.userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc: model.userinfo_encrypted_response_enc,
        request_object_signing_alg: model.request_object_signing_alg,
        request_object_encryption_alg: model.request_object_encryption_alg,
        request_object_encryption_enc: model.request_object_encryption_enc,
        token_endpoint_auth_method: model.token_endpoint_auth_method,
        token_endpoint_auth_signing_alg: model.token_endpoint_auth_signing_alg,
        default_max_age: model.default_max_age,
        require_auth_time: model.require_auth_time,
        default_acr_values: deserialize_optional_string_vec(model.default_acr_values.as_ref())?,
        initiate_login_uri: parse_optional_url(model.initiate_login_uri.as_deref())?,
        request_uris: parse_optional_urls(model.request_uris.as_ref())?,
        settings,
    })
}

fn to_platform(
    model: client_platform::Model,
) -> Result<OpenIdConnectClientPlatform, OpenIdConnectClientRepositoryError> {
    Ok(OpenIdConnectClientPlatform {
        platform: model
            .platform
            .parse::<OpenIdConnectClientPlatformType>()
            .map_err(OpenIdConnectClientRepositoryError::ParseClientPlatform)?,
        redirect_uris: parse_optional_urls(model.redirect_uris.as_ref())?.unwrap_or_default(),
    })
}

pub struct OpenIdConnectClientRepositoryImpl {
    db: DatabaseConnection,
}

impl OpenIdConnectClientRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for OpenIdConnectClientRepositoryImpl {
    async fn find_by_oid(
        &self,
        oid: crate::domain::client::model::ClientOid,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let row = ClientEntity::find()
            .filter(client::Column::Oid.eq(oid))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .find_also_related(OpenIdConnectClientEntity)
            .one(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?;

        let Some((client_model, metadata_model)) = row else {
            return Ok(None);
        };

        let Some(metadata_model) = metadata_model else {
            return Err(OpenIdConnectClientRepositoryError::MissingMetadata(oid));
        };

        let client_id = client_model.id;
        let platform_models = ClientPlatformEntity::find()
            .filter(client_platform::Column::ClientId.eq(client_id))
            .all(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?;
        let platforms = platform_models
            .into_iter()
            .map(to_platform)
            .collect::<Result<Vec<_>, _>>()?;

        let assigned_scopes = ScopeEntity::find()
            .inner_join(ClientScopeEntity)
            .filter(client_scope::Column::ClientId.eq(client_id))
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .select_only()
            .column(scope::Column::Name)
            .into_tuple::<String>()
            .all(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?;

        let client = to_client(client_model)?;
        let metadata = to_metadata(metadata_model)?;
        Ok(Some(
            OpenIdConnectClient::new(client, metadata, platforms, assigned_scopes)
                .map_err(OpenIdConnectClientRepositoryError::InvalidClient)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        deserialize_optional_string_vec, parse_optional_url, parse_optional_urls, to_platform,
    };
    use crate::{
        domain::openid_connect::OpenIdConnectClientPlatformType,
        infrastructure::database::entity::client_platform,
    };
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn parses_json_array_to_optional_vec() {
        let values = deserialize_optional_string_vec(Some(&json!(["a", "b"]))).unwrap();
        assert_eq!(values, Some(vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn parses_url_field() {
        let url = parse_optional_url(Some("https://example.com/callback")).unwrap();
        assert_eq!(url.unwrap().as_str(), "https://example.com/callback");
    }

    #[test]
    fn parses_url_arrays_without_dropping_entries() {
        let urls = parse_optional_urls(Some(&json!([
            "https://example.com/a",
            "https://example.com/b"
        ])))
        .unwrap();
        assert_eq!(urls.unwrap().len(), 2);
    }

    #[test]
    fn maps_client_platform_redirect_uris() {
        let platform = to_platform(client_platform::Model {
            id: 1,
            client_id: 2,
            platform: "web".to_string(),
            redirect_uris: Some(json!(["https://example.com/callback"])),
            created_at: Utc::now().into(),
            updated_at: None,
        })
        .unwrap();

        assert_eq!(platform.platform, OpenIdConnectClientPlatformType::Web);
        assert_eq!(
            platform.redirect_uris[0].as_str(),
            "https://example.com/callback"
        );
    }

    #[test]
    fn rejects_unknown_client_platform() {
        let error = to_platform(client_platform::Model {
            id: 1,
            client_id: 2,
            platform: "ios".to_string(),
            redirect_uris: Some(json!(["com.example.app:/callback"])),
            created_at: Utc::now().into(),
            updated_at: None,
        })
        .unwrap_err();

        assert!(matches!(
            error,
            crate::domain::openid_connect::OpenIdConnectClientRepositoryError::ParseClientPlatform(
                _
            )
        ));
    }
}
