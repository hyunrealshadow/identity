use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::database::entity::{client, client_open_id_connect_credential};
use identity_domain::client::model::ClientOid;
use identity_domain::openid_connect::{
    OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialOid,
    OpenIdConnectCredentialRepository, OpenIdConnectCredentialRepositoryError,
    OpenIdConnectCredentialType,
};

#[derive(Debug, Deserialize)]
struct RawClientSecretData {
    secret: String,
}

#[derive(Debug, Deserialize)]
struct RawClientPublicKeyData {
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct RawClientJsonWebKeySetData {
    jwks_uri: String,
    last_updated: String,
    expires_at: String,
    public_keys: Vec<String>,
}

fn deserialize_data(
    type_: &OpenIdConnectCredentialType,
    raw: &Value,
) -> Result<OpenIdConnectCredentialData, OpenIdConnectCredentialRepositoryError> {
    match type_ {
        OpenIdConnectCredentialType::ClientSecret => {
            serde_json::from_value::<RawClientSecretData>(raw.clone())
                .map(|data| OpenIdConnectCredentialData::ClientSecret {
                    secret: data.secret,
                })
                .map_err(OpenIdConnectCredentialRepositoryError::DeserializeData)
        }
        OpenIdConnectCredentialType::ClientPublicKey => {
            serde_json::from_value::<RawClientPublicKeyData>(raw.clone())
                .map(|data| OpenIdConnectCredentialData::ClientPublicKey {
                    public_key: data.public_key,
                })
                .map_err(OpenIdConnectCredentialRepositoryError::DeserializeData)
        }
        OpenIdConnectCredentialType::ClientJsonWebKeySet => {
            serde_json::from_value::<RawClientJsonWebKeySetData>(raw.clone())
                .map_err(OpenIdConnectCredentialRepositoryError::DeserializeData)
                .and_then(|data| {
                    let jwks_uri = Url::parse(&data.jwks_uri)
                        .map_err(OpenIdConnectCredentialRepositoryError::ParseUrl)?;
                    let last_updated = DateTime::parse_from_rfc3339(&data.last_updated)
                        .map_err(OpenIdConnectCredentialRepositoryError::ParseDateTime)?
                        .with_timezone(&Utc);
                    let expires_at = DateTime::parse_from_rfc3339(&data.expires_at)
                        .map_err(OpenIdConnectCredentialRepositoryError::ParseDateTime)?
                        .with_timezone(&Utc);
                    Ok(OpenIdConnectCredentialData::ClientJsonWebKeySet {
                        jwks_uri,
                        last_updated,
                        expires_at,
                        public_keys: data.public_keys,
                    })
                })
        }
    }
}

fn to_domain(
    client_oid: ClientOid,
    model: client_open_id_connect_credential::Model,
) -> Result<OpenIdConnectCredential, OpenIdConnectCredentialRepositoryError> {
    let type_: OpenIdConnectCredentialType = model
        .r#type
        .parse()
        .map_err(OpenIdConnectCredentialRepositoryError::ParseCredentialType)?;

    Ok(OpenIdConnectCredential {
        oid: model.oid,
        client_oid,
        r#type: type_.clone(),
        hint: model.hint,
        data: deserialize_data(&type_, &model.data)?,
        expires_at: model.expires_at.with_timezone(&Utc),
        revoked_at: model.revoked_at.map(|v| v.with_timezone(&Utc)),
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|v| v.with_timezone(&Utc)),
    })
}

pub struct OpenIdConnectCredentialRepositoryImpl {
    db: DatabaseConnection,
}

impl OpenIdConnectCredentialRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl OpenIdConnectCredentialRepository for OpenIdConnectCredentialRepositoryImpl {
    async fn find_by_oid(
        &self,
        oid: OpenIdConnectCredentialOid,
    ) -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        let row = client_open_id_connect_credential::Entity::find()
            .find_also_related(crate::database::entity::client::Entity)
            .filter(client_open_id_connect_credential::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(OpenIdConnectCredentialRepositoryError::QueryFailed)?;

        let Some((model, client)) = row else {
            return Ok(None);
        };

        let Some(client) = client else {
            return Err(OpenIdConnectCredentialRepositoryError::MissingClient);
        };

        to_domain(client.oid, model).map(Some)
    }

    async fn find_by_client_oid_and_type(
        &self,
        client_oid: ClientOid,
        type_: OpenIdConnectCredentialType,
    ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        let rows = client::Entity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .inner_join(client_open_id_connect_credential::Entity)
            .filter(client_open_id_connect_credential::Column::Type.eq(type_.to_string()))
            .select_only()
            .columns([
                client_open_id_connect_credential::Column::Id,
                client_open_id_connect_credential::Column::Oid,
                client_open_id_connect_credential::Column::ClientId,
                client_open_id_connect_credential::Column::Type,
                client_open_id_connect_credential::Column::Data,
                client_open_id_connect_credential::Column::Hint,
                client_open_id_connect_credential::Column::ExpiresAt,
                client_open_id_connect_credential::Column::RevokedAt,
                client_open_id_connect_credential::Column::CreatedAt,
                client_open_id_connect_credential::Column::UpdatedAt,
            ])
            .into_model::<client_open_id_connect_credential::Model>()
            .all(&self.db)
            .await
            .map_err(OpenIdConnectCredentialRepositoryError::QueryFailed)?;

        Ok(rows
            .into_iter()
            .map(|model| to_domain(client_oid, model))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::deserialize_data;
    use identity_domain::openid_connect::OpenIdConnectCredentialType;
    use serde_json::json;

    #[test]
    fn deserializes_client_secret() {
        let data = deserialize_data(
            &OpenIdConnectCredentialType::ClientSecret,
            &json!({"secret":"s3cr3t"}),
        )
        .unwrap();

        assert!(
            matches!(data, identity_domain::openid_connect::OpenIdConnectCredentialData::ClientSecret { secret } if secret == "s3cr3t")
        );
    }
}
