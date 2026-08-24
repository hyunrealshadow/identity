use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::database::entity::{client, client_open_id_connect_credential};
use identity_domain::client::model::ClientOid;
use identity_domain::key::PublicJwk;
use identity_domain::openid_connect::{
    OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
    OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
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
            data: serde_json::json!({ "secret": secret }),
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
                data: serde_json::json!({
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
            data: serde_json::json!({
                "jwks_uri": jwks_uri,
                "last_updated": last_updated,
                "expires_at": expires_at,
                "public_keys": public_keys,
                "jwks": jwks,
            }),
        },
    }
}

fn masked_client_secret_hint(secret: &str) -> String {
    let suffix = if secret.chars().count() > 4 {
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
    };
    format!("••••{suffix}")
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
                    jwk: data.jwk,
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
                        jwks: data.jwks,
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
    async fn find_active_by_client_oid_and_type(
        &self,
        client_oid: ClientOid,
        type_: OpenIdConnectCredentialType,
    ) -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError> {
        let rows = client::Entity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .inner_join(client_open_id_connect_credential::Entity)
            .filter(client_open_id_connect_credential::Column::Type.eq(type_.to_string()))
            .filter(client_open_id_connect_credential::Column::RevokedAt.is_null())
            .filter(client_open_id_connect_credential::Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(client_open_id_connect_credential::Column::CreatedAt)
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
            .map_err(|e| OpenIdConnectCredentialRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(rows
            .into_iter()
            .map(|model| to_domain(client_oid, model))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenIdConnectCredentialRepositoryImpl, deserialize_data, serialize_data};
    use crate::database::entity::client_open_id_connect_credential;
    use identity_domain::openid_connect::{
        OpenIdConnectCredentialRepository as _, OpenIdConnectCredentialType,
    };
    use sea_orm::{DatabaseBackend, MockDatabase};
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

    #[test]
    fn serializes_client_secret_with_a_masked_hint() {
        let serialized = serialize_data(
            identity_domain::openid_connect::OpenIdConnectCredentialData::ClientSecret {
                secret: "long-secret-value".to_owned(),
            },
        );

        assert_eq!(serialized.hint, "••••alue");
        assert_eq!(serialized.data, json!({"secret": "long-secret-value"}));

        let short = serialize_data(
            identity_domain::openid_connect::OpenIdConnectCredentialData::ClientSecret {
                secret: "tiny".to_owned(),
            },
        );
        assert_eq!(short.hint, "••••");
    }

    #[tokio::test]
    async fn active_lookup_filters_lifecycle_and_prefers_newest_credentials() {
        let now = chrono::Utc::now();
        let model = client_open_id_connect_credential::Model {
            id: 1,
            oid: uuid::Uuid::new_v4(),
            client_id: 1,
            r#type: "client_secret".to_owned(),
            data: json!({"secret": "secret"}),
            hint: "••••cret".to_owned(),
            expires_at: (now + chrono::Duration::days(1)).into(),
            revoked_at: None,
            created_at: now.into(),
            updated_at: None,
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![model]])
            .into_connection();
        let repo = OpenIdConnectCredentialRepositoryImpl::new(db);

        let credentials = repo
            .find_active_by_client_oid_and_type(
                uuid::Uuid::nil(),
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .unwrap();

        assert_eq!(credentials.len(), 1);
        let statements = format!("{:?}", repo.db.into_transaction_log());
        assert!(statements.contains("revoked_at"));
        assert!(statements.contains("expires_at"));
        assert!(statements.contains("ORDER BY"));
        assert!(statements.contains("created_at"));
        assert!(statements.contains("DESC"));
    }
}
