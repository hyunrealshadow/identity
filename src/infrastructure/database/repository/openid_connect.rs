use async_trait::async_trait;
use chrono::Duration;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity, client_open_id_connect,
    client_open_id_connect::Entity as OpenIdConnectClientEntity, client_open_id_connect_credential,
    client_platform, client_platform::Entity as ClientPlatformEntity, client_scope,
    client_scope::Entity as ClientScopeEntity, login, login::Entity as LoginEntity, scope,
    scope::Entity as ScopeEntity, session, session::Entity as SessionEntity,
};
use identity_domain::auth::SessionOid;
use identity_domain::client::model::Client;
use identity_domain::openid_connect::{
    OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
    OpenIdConnectClientPlatformType, OpenIdConnectClientRegistration,
    OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepository,
    OpenIdConnectClientRepositoryError, OpenIdConnectClientSettings, OpenIdConnectCredentialData,
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
        frontchannel_logout_uri: parse_optional_url(model.frontchannel_logout_uri.as_deref())?,
        frontchannel_logout_session_required: model.frontchannel_logout_session_required,
        backchannel_logout_uri: parse_optional_url(model.backchannel_logout_uri.as_deref())?,
        backchannel_logout_session_required: model.backchannel_logout_session_required,
        response_types: deserialize_optional_string_vec(model.response_types.as_ref())?,
        grant_types: deserialize_optional_string_vec(model.grant_types.as_ref())?,
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

fn optional_urls_to_json(value: Option<Vec<Url>>) -> Option<Value> {
    value.map(|urls| {
        Value::Array(
            urls.into_iter()
                .map(|url| Value::String(url.to_string()))
                .collect(),
        )
    })
}

fn optional_strings_to_json(value: Option<Vec<String>>) -> Option<Value> {
    value.map(|items| Value::Array(items.into_iter().map(Value::String).collect()))
}

fn urls_to_json(value: Vec<Url>) -> Option<Value> {
    (!value.is_empty()).then(|| {
        Value::Array(
            value
                .into_iter()
                .map(|url| Value::String(url.to_string()))
                .collect(),
        )
    })
}

#[async_trait]
impl OpenIdConnectClientRegistrationRepository for OpenIdConnectClientRepositoryImpl {
    async fn create(
        &self,
        registration: OpenIdConnectClientRegistration,
    ) -> Result<identity_domain::client::model::ClientOid, OpenIdConnectClientRepositoryError> {
        let client_oid = registration.client.oid;
        let now = Utc::now();

        self.db
            .transaction::<_, _, sea_orm::DbErr>(|txn| {
                Box::pin(async move {
                    let client_model = client::ActiveModel {
                        oid: Set(registration.client.oid),
                        protocol: Set(registration.client.protocol.to_string()),
                        name: Set(registration.client.name),
                        names: Set(optional_strings_to_json(Some(registration.client.names))),
                        description: Set(registration.client.description),
                        created_at: Set(registration.client.created_at.naive_utc()),
                        updated_at: Set(registration
                            .client
                            .updated_at
                            .map(|value| value.naive_utc())),
                        ..Default::default()
                    }
                    .insert(txn)
                    .await?;

                    let metadata = registration.metadata;
                    let settings = serde_json::to_value(metadata.settings)
                        .map_err(|error| sea_orm::DbErr::Custom(error.to_string()))?;
                    client_open_id_connect::ActiveModel {
                        client_id: Set(client_model.id),
                        post_logout_redirect_uris: Set(optional_urls_to_json(
                            metadata.post_logout_redirect_uris,
                        )),
                        frontchannel_logout_uri: Set(metadata
                            .frontchannel_logout_uri
                            .map(|value| value.to_string())),
                        frontchannel_logout_session_required: Set(
                            metadata.frontchannel_logout_session_required
                        ),
                        backchannel_logout_uri: Set(metadata
                            .backchannel_logout_uri
                            .map(|value| value.to_string())),
                        backchannel_logout_session_required: Set(
                            metadata.backchannel_logout_session_required
                        ),
                        response_types: Set(optional_strings_to_json(metadata.response_types)),
                        grant_types: Set(optional_strings_to_json(metadata.grant_types)),
                        contacts: Set(optional_strings_to_json(metadata.contacts)),
                        logo_uri: Set(metadata.logo_uri.map(|value| value.to_string())),
                        client_uri: Set(metadata.client_uri.map(|value| value.to_string())),
                        policy_uri: Set(metadata.policy_uri.map(|value| value.to_string())),
                        tos_uri: Set(metadata.tos_uri.map(|value| value.to_string())),
                        sector_identifier_uri: Set(metadata
                            .sector_identifier_uri
                            .map(|value| value.to_string())),
                        subject_type: Set(metadata.subject_type.map(|value| value.to_string())),
                        id_token_signed_response_alg: Set(metadata.id_token_signed_response_alg),
                        id_token_encrypted_response_alg: Set(
                            metadata.id_token_encrypted_response_alg
                        ),
                        id_token_encrypted_response_enc: Set(
                            metadata.id_token_encrypted_response_enc
                        ),
                        userinfo_signed_response_alg: Set(metadata.userinfo_signed_response_alg),
                        userinfo_encrypted_response_alg: Set(
                            metadata.userinfo_encrypted_response_alg
                        ),
                        userinfo_encrypted_response_enc: Set(
                            metadata.userinfo_encrypted_response_enc
                        ),
                        request_object_signing_alg: Set(metadata.request_object_signing_alg),
                        request_object_encryption_alg: Set(metadata.request_object_encryption_alg),
                        request_object_encryption_enc: Set(metadata.request_object_encryption_enc),
                        token_endpoint_auth_method: Set(metadata.token_endpoint_auth_method),
                        token_endpoint_auth_signing_alg: Set(
                            metadata.token_endpoint_auth_signing_alg
                        ),
                        default_max_age: Set(metadata.default_max_age),
                        require_auth_time: Set(metadata.require_auth_time),
                        default_acr_values: Set(optional_strings_to_json(
                            metadata.default_acr_values,
                        )),
                        initiate_login_uri: Set(metadata
                            .initiate_login_uri
                            .map(|value| value.to_string())),
                        request_uris: Set(optional_urls_to_json(metadata.request_uris)),
                        settings: Set(settings),
                        created_at: Set(now.into()),
                        updated_at: Set(None),
                        ..Default::default()
                    }
                    .insert(txn)
                    .await?;

                    for platform in registration.platforms {
                        client_platform::ActiveModel {
                            client_id: Set(client_model.id),
                            platform: Set(platform.platform.to_string()),
                            redirect_uris: Set(urls_to_json(platform.redirect_uris)),
                            created_at: Set(now.into()),
                            updated_at: Set(None),
                            ..Default::default()
                        }
                        .insert(txn)
                        .await?;
                    }

                    if !registration.assigned_scopes.is_empty() {
                        let scope_models = ScopeEntity::find()
                            .filter(scope::Column::Protocol.eq("openid_connect"))
                            .filter(scope::Column::Name.is_in(registration.assigned_scopes))
                            .all(txn)
                            .await?;
                        for scope_model in scope_models {
                            client_scope::ActiveModel {
                                client_id: Set(client_model.id),
                                scope_id: Set(scope_model.id),
                                created_at: Set(now.into()),
                                ..Default::default()
                            }
                            .insert(txn)
                            .await?;
                        }
                    }

                    if let Some(secret) = registration.client_secret {
                        client_open_id_connect_credential::ActiveModel {
                            oid: Set(Uuid::new_v4()),
                            client_id: Set(client_model.id),
                            r#type: Set("client_secret".to_owned()),
                            data: Set(serde_json::json!({ "secret": secret })),
                            hint: Set(secret),
                            expires_at: Set((now + Duration::days(365)).into()),
                            revoked_at: Set(None),
                            created_at: Set(now.into()),
                            updated_at: Set(None),
                            ..Default::default()
                        }
                        .insert(txn)
                        .await?;
                    }

                    for credential in registration.credentials {
                        let (type_, hint, data) = match credential {
                            OpenIdConnectCredentialData::ClientSecret { secret } => (
                                "client_secret".to_owned(),
                                secret.clone(),
                                serde_json::json!({ "secret": secret }),
                            ),
                            OpenIdConnectCredentialData::ClientPublicKey { public_key, jwk } => (
                                "client_public_key".to_owned(),
                                jwk.as_ref()
                                    .and_then(|value| value.key_id())
                                    .or_else(|| jwk.as_ref().and_then(|value| value.algorithm()))
                                    .unwrap_or("client_public_key")
                                    .to_owned(),
                                serde_json::json!({
                                    "public_key": public_key,
                                    "jwk": jwk,
                                }),
                            ),
                            OpenIdConnectCredentialData::ClientJsonWebKeySet {
                                jwks_uri,
                                last_updated,
                                expires_at,
                                public_keys,
                                jwks,
                            } => (
                                "client_json_web_key_set".to_owned(),
                                jwks_uri.to_string(),
                                serde_json::json!({
                                    "jwks_uri": jwks_uri,
                                    "last_updated": last_updated,
                                    "expires_at": expires_at,
                                    "public_keys": public_keys,
                                    "jwks": jwks,
                                }),
                            ),
                        };

                        client_open_id_connect_credential::ActiveModel {
                            oid: Set(Uuid::new_v4()),
                            client_id: Set(client_model.id),
                            r#type: Set(type_),
                            data: Set(data),
                            hint: Set(hint),
                            expires_at: Set((now + Duration::days(365)).into()),
                            revoked_at: Set(None),
                            created_at: Set(now.into()),
                            updated_at: Set(None),
                            ..Default::default()
                        }
                        .insert(txn)
                        .await?;
                    }

                    let registration_access_token = registration.registration_access_token;
                    client_authorization::ActiveModel {
                        oid: Set(Uuid::new_v4()),
                        client_id: Set(client_model.id),
                        r#type: Set("registration_access_token".to_owned()),
                        data: Set(serde_json::json!({ "token": registration_access_token })),
                        expires_at: Set((now + Duration::days(365)).into()),
                        completed_at: Set(None),
                        revoked_at: Set(None),
                        created_at: Set(now.into()),
                        updated_at: Set(Some(now.into())),
                        ..Default::default()
                    }
                    .insert(txn)
                    .await?;

                    Ok(())
                })
            })
            .await
            .map_err(|error| {
                OpenIdConnectClientRepositoryError::QueryFailed(sea_orm::DbErr::Custom(
                    error.to_string(),
                ))
            })?;

        Ok(client_oid)
    }

    async fn find_by_registration_access_token(
        &self,
        client_oid: identity_domain::client::model::ClientOid,
        token: &str,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let Some(client_model) = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .one(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?
        else {
            return Ok(None);
        };

        let auth_rows = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::ClientId.eq(client_model.id))
            .filter(client_authorization::Column::Type.eq("registration_access_token"))
            .filter(client_authorization::Column::RevokedAt.is_null())
            .filter(client_authorization::Column::ExpiresAt.gt(Utc::now()))
            .all(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?;

        let valid = auth_rows.into_iter().any(|row| {
            row.data
                .get("token")
                .and_then(|value| value.as_str())
                .is_some_and(|stored| bool::from(subtle::ConstantTimeEq::ct_eq(stored.as_bytes(), token.as_bytes())))
        });

        if valid {
            self.find_by_oid(client_oid).await
        } else {
            Ok(None)
        }
    }

    async fn delete_by_oid(
        &self,
        client_oid: identity_domain::client::model::ClientOid,
    ) -> Result<(), OpenIdConnectClientRepositoryError> {
        let Some(client_model) = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .one(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?
        else {
            return Err(OpenIdConnectClientRepositoryError::ClientNotFound);
        };

        ClientEntity::delete_by_id(client_model.id)
            .exec(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?;

        Ok(())
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for OpenIdConnectClientRepositoryImpl {
    async fn find_by_oid(
        &self,
        oid: identity_domain::client::model::ClientOid,
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

    async fn find_frontchannel_logout_clients_by_session_oid(
        &self,
        session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        self.find_logout_clients_by_session_oid(session_oid, LogoutChannel::Front)
            .await
    }

    async fn find_backchannel_logout_clients_by_session_oid(
        &self,
        session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        self.find_logout_clients_by_session_oid(session_oid, LogoutChannel::Back)
            .await
    }
}

enum LogoutChannel {
    Front,
    Back,
}

impl OpenIdConnectClientRepositoryImpl {
    async fn find_logout_clients_by_session_oid(
        &self,
        session_oid: SessionOid,
        channel: LogoutChannel,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let Some(session_model) = SessionEntity::find()
            .filter(session::Column::Oid.eq(Uuid::from(session_oid)))
            .one(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?
        else {
            return Ok(Vec::new());
        };

        let client_ids = LoginEntity::find()
            .filter(login::Column::SessionId.eq(session_model.id))
            .select_only()
            .column(login::Column::ClientId)
            .into_tuple::<i64>()
            .all(&self.db)
            .await
            .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?;

        let mut clients = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for client_id in client_ids {
            if !seen.insert(client_id) {
                continue;
            }

            let Some(client_model) = ClientEntity::find_by_id(client_id)
                .one(&self.db)
                .await
                .map_err(OpenIdConnectClientRepositoryError::QueryFailed)?
            else {
                continue;
            };

            let Some(client) = self.find_by_oid(client_model.oid).await? else {
                continue;
            };

            let has_channel = match channel {
                LogoutChannel::Front => client.metadata().frontchannel_logout_uri.is_some(),
                LogoutChannel::Back => client.metadata().backchannel_logout_uri.is_some(),
            };
            if has_channel {
                clients.push(client);
            }
        }

        Ok(clients)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        deserialize_optional_string_vec, parse_optional_url, parse_optional_urls, to_metadata,
        to_platform,
    };
    use crate::{
        domain::openid_connect::OpenIdConnectClientPlatformType,
        infrastructure::database::entity::{client_open_id_connect, client_platform},
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
    fn maps_logout_metadata() {
        let metadata = to_metadata(client_open_id_connect::Model {
            id: 1,
            client_id: 2,
            post_logout_redirect_uris: None,
            frontchannel_logout_uri: Some("https://rp.example.com/frontchannel_logout".to_owned()),
            frontchannel_logout_session_required: Some(true),
            backchannel_logout_uri: Some("https://rp.example.com/backchannel_logout".to_owned()),
            backchannel_logout_session_required: Some(true),
            response_types: None,
            grant_types: None,
            contacts: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: json!({}),
            created_at: Utc::now().into(),
            updated_at: None,
        })
        .unwrap();

        assert_eq!(
            metadata.frontchannel_logout_uri.unwrap().as_str(),
            "https://rp.example.com/frontchannel_logout"
        );
        assert_eq!(metadata.frontchannel_logout_session_required, Some(true));
        assert_eq!(
            metadata.backchannel_logout_uri.unwrap().as_str(),
            "https://rp.example.com/backchannel_logout"
        );
        assert_eq!(metadata.backchannel_logout_session_required, Some(true));
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
            identity_domain::openid_connect::OpenIdConnectClientRepositoryError::ParseClientPlatform(
                _
            )
        ));
    }
}
