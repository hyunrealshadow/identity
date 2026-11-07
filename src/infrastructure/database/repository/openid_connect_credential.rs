use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::{
    client::model::ClientOid,
    key::PublicJwk,
    openid_connect::{
        OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
        OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
    },
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;
use serde_json::{Value, from_value, json};
use url::Url;

use crate::database::entity::{
    client::{Column as ClientColumn, Entity as ClientEntity},
    client_openid_connect_credential,
    client_openid_connect_credential::Column as ClientOpenIdConnectCredentialColumn,
};

#[derive(Debug, Deserialize)]
struct RawClientSecretData {
    secret: String,
}

#[derive(Debug, Deserialize)]
struct RawClientPublicKeyData {
    public_key: String,
    #[serde(default)]
    jwk: Option<PublicJwk>,
}

#[derive(Debug, Deserialize)]
struct RawClientJsonWebKeySetData {
    jwks_uri: String,
    last_updated: String,
    expires_at: String,
    public_keys: Vec<String>,
    #[serde(default)]
    jwks: Vec<PublicJwk>,
}

pub(crate) struct SerializedCredentialData {
    pub type_: String,
    pub data: Value,
    pub hint: String,
}

pub(crate) fn serialize_data(credential: OpenIdConnectCredentialData) -> SerializedCredentialData {
    match credential {
        OpenIdConnectCredentialData::ClientSecret { secret } => SerializedCredentialData {
            type_: OpenIdConnectCredentialType::ClientSecret.to_string(),
            hint: masked_client_secret_hint(&secret),
            data: json!({ "secret": secret }),
        },
        OpenIdConnectCredentialData::ClientPublicKey { public_key, jwk } => {
            let hint = jwk
                .as_ref()
                .and_then(|value| value.key_id())
                .or_else(|| jwk.as_ref().and_then(|value| value.algorithm()))
                .unwrap_or("client_public_key")
                .to_owned();
            SerializedCredentialData {
                type_: OpenIdConnectCredentialType::ClientPublicKey.to_string(),
                hint,
                data: json!({
                    "public_key": public_key,
                    "jwk": jwk,
                }),
            }
        }
        OpenIdConnectCredentialData::ClientJsonWebKeySet {
            jwks_uri,
            last_updated,
            expires_at,
            public_keys,
            jwks,
        } => SerializedCredentialData {
            type_: OpenIdConnectCredentialType::ClientJsonWebKeySet.to_string(),
            hint: jwks_uri.to_string(),
            data: json!({
                "jwks_uri": jwks_uri,
                "last_updated": last_updated,
                "expires_at": expires_at,
                "public_keys": public_keys,
                "jwks": jwks,
            }),
        },
    }
}

/// The last four characters identify a secret; the presentation adds the
/// mask. A secret too short to reveal part of it gets an empty hint.
fn masked_client_secret_hint(secret: &str) -> String {
    if secret.chars().count() > 4 {
        secret
            .chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect()
    } else {
        String::new()
    }
}

fn deserialize_data(
    type_: &OpenIdConnectCredentialType,
    raw: &Value,
) -> Result<OpenIdConnectCredentialData, OpenIdConnectCredentialRepositoryError> {
    match type_ {
        OpenIdConnectCredentialType::ClientSecret => from_value::<RawClientSecretData>(raw.clone())
            .map(|data| OpenIdConnectCredentialData::ClientSecret {
                secret: data.secret,
            })
            .map_err(OpenIdConnectCredentialRepositoryError::DeserializeData),
        OpenIdConnectCredentialType::ClientPublicKey => {
            from_value::<RawClientPublicKeyData>(raw.clone())
                .map(|data| OpenIdConnectCredentialData::ClientPublicKey {
                    public_key: data.public_key,
                    jwk: data.jwk,
                })
                .map_err(OpenIdConnectCredentialRepositoryError::DeserializeData)
        }
        OpenIdConnectCredentialType::ClientJsonWebKeySet => {
            from_value::<RawClientJsonWebKeySetData>(raw.clone())
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
                        jwks: data.jwks,
                    })
                })
        }
    }
}

fn to_domain(
    client_oid: ClientOid,
    model: client_openid_connect_credential::Model,
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
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_active_by_client_oid_and_type"))]
    async fn find_active_by_client_oid_and_type(
        &self,
        client_oid: ClientOid,
        type_: OpenIdConnectCredentialType,
    ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        let rows = ClientEntity::find()
            .filter(ClientColumn::Oid.eq(client_oid))
            .filter(ClientColumn::Protocol.eq("openid_connect"))
            .inner_join(client_openid_connect_credential::Entity)
            .filter(ClientOpenIdConnectCredentialColumn::Type.eq(type_.to_string()))
            .filter(ClientOpenIdConnectCredentialColumn::RevokedAt.is_null())
            .filter(ClientOpenIdConnectCredentialColumn::ExpiresAt.gt(Utc::now()))
            .order_by_desc(ClientOpenIdConnectCredentialColumn::CreatedAt)
            .select_only()
            .columns([
                ClientOpenIdConnectCredentialColumn::Id,
                ClientOpenIdConnectCredentialColumn::Oid,
                ClientOpenIdConnectCredentialColumn::ClientId,
                ClientOpenIdConnectCredentialColumn::Type,
                ClientOpenIdConnectCredentialColumn::Data,
                ClientOpenIdConnectCredentialColumn::Hint,
                ClientOpenIdConnectCredentialColumn::ExpiresAt,
                ClientOpenIdConnectCredentialColumn::RevokedAt,
                ClientOpenIdConnectCredentialColumn::CreatedAt,
                ClientOpenIdConnectCredentialColumn::UpdatedAt,
            ])
            .into_model::<client_openid_connect_credential::Model>()
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectCredentialRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(rows
            .into_iter()
            .map(|model| to_domain(client_oid, model))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use identity_domain::openid_connect::{
        OpenIdConnectCredentialData, OpenIdConnectCredentialType,
    };
    use serde_json::json;

    use super::{deserialize_data, serialize_data};

    #[test]
    fn deserializes_client_secret() {
        let data = deserialize_data(
            &OpenIdConnectCredentialType::ClientSecret,
            &json!({"secret":"s3cr3t"}),
        )
        .unwrap();

        assert!(
            matches!(data, OpenIdConnectCredentialData::ClientSecret { secret } if secret == "s3cr3t")
        );
    }

    #[test]
    fn serializes_client_secret_with_a_masked_hint() {
        let serialized = serialize_data(OpenIdConnectCredentialData::ClientSecret {
            secret: "long-secret-value".to_owned(),
        });

        assert_eq!(serialized.hint, "alue");
        assert_eq!(serialized.data, json!({"secret": "long-secret-value"}));

        let short = serialize_data(OpenIdConnectCredentialData::ClientSecret {
            secret: "tiny".to_owned(),
        });
        assert_eq!(short.hint, "");
    }
}
