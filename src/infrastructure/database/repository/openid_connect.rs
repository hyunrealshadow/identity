use async_trait::async_trait;
use chrono::Duration;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity, client_openid_connect,
    client_openid_connect::Entity as OpenIdConnectClientEntity, client_openid_connect_cors_origin,
    client_openid_connect_credential, client_openid_connect_platform,
    client_openid_connect_platform::Entity as ClientOpenIdConnectPlatformEntity, client_scope,
    client_scope::Entity as ClientScopeEntity, login, login::Entity as LoginEntity, scope,
    scope::Entity as ScopeEntity, session, session::Entity as SessionEntity,
};
use identity_domain::auth::SessionOid;
use identity_domain::client::model::Client;
use identity_domain::client_authorization::ClientAuthorizationType;
use identity_domain::openid_connect::{
    OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
    OpenIdConnectClientPlatformType, OpenIdConnectClientRegistration,
    OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepository,
    OpenIdConnectClientRepositoryError, OpenIdConnectClientSettings,
};

use super::{
    openid_connect_credential::serialize_data as serialize_credential_data,
    shared::non_expiring_timestamp,
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

fn parse_optional_redirect_uris(
    raw: Option<&Value>,
) -> Result<Vec<String>, OpenIdConnectClientRepositoryError> {
    let values = deserialize_optional_string_vec(raw)?.unwrap_or_default();
    for value in &values {
        Url::parse(value).map_err(OpenIdConnectClientRepositoryError::ParseUrl)?;
    }
    Ok(values)
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
        built_in: model.built_in,
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|v| v.with_timezone(&Utc)),
    })
}

fn to_metadata(
    model: client_openid_connect::Model,
) -> Result<OpenIdConnectClientMetadata, OpenIdConnectClientRepositoryError> {
    let settings = serde_json::from_value::<OpenIdConnectClientSettings>(model.settings)
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

fn parse_metadata_values<T: std::str::FromStr>(
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

fn to_platform(
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

fn redirect_uris_to_json(value: Vec<String>) -> Option<Value> {
    (!value.is_empty()).then(|| Value::Array(value.into_iter().map(Value::String).collect()))
}

fn optional_metadata_values_to_json<T: ToString>(value: Option<Vec<T>>) -> Option<Value> {
    optional_strings_to_json(
        value.map(|items| items.into_iter().map(|item| item.to_string()).collect()),
    )
}

fn cors_origins_for_client(
    settings: &OpenIdConnectClientSettings,
    platforms: &[OpenIdConnectClientPlatform],
) -> Vec<String> {
    if !settings.cors_enabled {
        return Vec::new();
    }

    let mut origins: Vec<_> = platforms
        .iter()
        .flat_map(|platform| &platform.redirect_uris)
        .filter_map(|uri| Url::parse(uri).ok())
        .filter(|uri| matches!(uri.scheme(), "http" | "https"))
        .map(|uri| uri.origin().ascii_serialization())
        .collect();
    origins.sort_unstable();
    origins.dedup();
    origins
}

impl OpenIdConnectClientRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "create"))]
    async fn persist_registration(
        &self,
        registration: OpenIdConnectClientRegistration,
        update_auth: Option<(String, Option<String>)>,
    ) -> Result<identity_domain::client::model::ClientOid, OpenIdConnectClientRepositoryError> {
        let client_oid = registration.client.oid;
        let now = Utc::now();
        let cors_origins =
            cors_origins_for_client(&registration.metadata.settings, &registration.platforms);

        self.db
            .transaction::<_, _, sea_orm::DbErr>(|txn| {
                Box::pin(async move {
                    let existing = if let Some((token, secret)) = &update_auth {
                        let existing = ClientEntity::find().filter(client::Column::Oid.eq(client_oid))
                            .lock_exclusive().one(txn).await?
                            .ok_or_else(|| sea_orm::DbErr::Custom("registration_invalid_token".into()))?;
                        if existing.built_in { return Err(sea_orm::DbErr::Custom("registration_invalid_token".into())); }
                        let rows = ClientAuthorizationEntity::find()
                            .filter(client_authorization::Column::ClientId.eq(existing.id))
                            .filter(client_authorization::Column::Type.eq(ClientAuthorizationType::RegistrationAccessToken.to_string()))
                            .filter(client_authorization::Column::RevokedAt.is_null())
                            .filter(client_authorization::Column::ExpiresAt.gt(now)).all(txn).await?;
                        let valid = rows.iter().any(|row| row.data.get("token").and_then(Value::as_str)
                            .is_some_and(|stored| bool::from(subtle::ConstantTimeEq::ct_eq(stored.as_bytes(), token.as_bytes()))));
                        if !valid { return Err(sea_orm::DbErr::Custom("registration_invalid_token".into())); }
                        if let Some(secret) = secret {
                            let rows = client_openid_connect_credential::Entity::find()
                                .filter(client_openid_connect_credential::Column::ClientId.eq(existing.id))
                                .filter(client_openid_connect_credential::Column::Type.eq("client_secret"))
                                .filter(client_openid_connect_credential::Column::RevokedAt.is_null())
                                .filter(client_openid_connect_credential::Column::ExpiresAt.gt(now)).all(txn).await?;
                            let valid = rows.iter().any(|row| row.data.get("secret").and_then(Value::as_str)
                                .is_some_and(|stored| bool::from(subtle::ConstantTimeEq::ct_eq(stored.as_bytes(), secret.as_bytes()))));
                            if !valid { return Err(sea_orm::DbErr::Custom("registration_invalid_secret".into())); }
                        }
                        OpenIdConnectClientEntity::delete_many().filter(client_openid_connect::Column::ClientId.eq(existing.id)).exec(txn).await?;
                        ClientOpenIdConnectPlatformEntity::delete_many().filter(client_openid_connect_platform::Column::ClientId.eq(existing.id)).exec(txn).await?;
                        ClientScopeEntity::delete_many().filter(client_scope::Column::ClientId.eq(existing.id)).exec(txn).await?;
                        client_openid_connect_cors_origin::Entity::delete_many().filter(client_openid_connect_cors_origin::Column::ClientId.eq(existing.id)).exec(txn).await?;
                        client_openid_connect_credential::Entity::delete_many().filter(client_openid_connect_credential::Column::ClientId.eq(existing.id)).exec(txn).await?;
                        Some(existing)
                    } else { None };
                    let client_model = client::ActiveModel {
                        id: existing.as_ref().map(|model| Set(model.id)).unwrap_or_default(),
                        oid: Set(registration.client.oid),
                        protocol: Set(registration.client.protocol.to_string()),
                        name: Set(registration.client.name),
                        names: Set(optional_strings_to_json(Some(registration.client.names))),
                        description: Set(registration.client.description),
                        built_in: Set(registration.client.built_in),
                        created_at: Set(registration.client.created_at.into()),
                        updated_at: Set(registration.client.updated_at.map(Into::into)),
                        ..Default::default()
                    };
                    let client_model = if existing.is_some() {
                        client_model.update(txn).await?
                    } else {
                        client_model.insert(txn).await?
                    };

                    let metadata = registration.metadata;
                    let settings = serde_json::to_value(metadata.settings)
                        .map_err(|error| sea_orm::DbErr::Custom(error.to_string()))?;
                    client_openid_connect::ActiveModel {
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
                        response_types: Set(optional_strings_to_json(metadata.response_types.map(
                            |values| values.into_iter().map(|value| value.to_string()).collect()
                        ))),
                        grant_types: Set(optional_strings_to_json(metadata.grant_types.map(
                            |values| values.into_iter().map(|value| value.to_string()).collect()
                        ))),
                        contacts: Set(optional_strings_to_json(metadata.contacts)),
                        logo_uri: Set(metadata.logo_uri.map(|value| value.to_string())),
                        client_uri: Set(metadata.client_uri.map(|value| value.to_string())),
                        policy_uri: Set(metadata.policy_uri.map(|value| value.to_string())),
                        tos_uri: Set(metadata.tos_uri.map(|value| value.to_string())),
                        sector_identifier_uri: Set(metadata
                            .sector_identifier_uri
                            .map(|value| value.to_string())),
                        subject_type: Set(metadata.subject_type.map(|value| value.to_string())),
                        id_token_signed_response_algs: Set(optional_metadata_values_to_json(metadata.id_token_signed_response_algs)),
                        id_token_encrypted_response_algs: Set(optional_metadata_values_to_json(metadata.id_token_encrypted_response_algs)),
                        id_token_encrypted_response_encs: Set(optional_metadata_values_to_json(metadata.id_token_encrypted_response_encs)),
                        userinfo_signed_response_algs: Set(optional_metadata_values_to_json(metadata.userinfo_signed_response_algs)),
                        userinfo_encrypted_response_algs: Set(optional_metadata_values_to_json(metadata.userinfo_encrypted_response_algs)),
                        userinfo_encrypted_response_encs: Set(optional_metadata_values_to_json(metadata.userinfo_encrypted_response_encs)),
                        request_object_signing_algs: Set(optional_metadata_values_to_json(metadata.request_object_signing_algs)),
                        request_object_encryption_algs: Set(optional_metadata_values_to_json(metadata.request_object_encryption_algs)),
                        request_object_encryption_encs: Set(optional_metadata_values_to_json(metadata.request_object_encryption_encs)),
                        token_endpoint_auth_methods: Set(optional_metadata_values_to_json(metadata.token_endpoint_auth_methods)),
                        token_endpoint_auth_signing_algs: Set(optional_metadata_values_to_json(metadata.token_endpoint_auth_signing_algs)),
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
                        client_openid_connect_platform::ActiveModel {
                            client_id: Set(client_model.id),
                            platform: Set(platform.platform.to_string()),
                            redirect_uris: Set(redirect_uris_to_json(platform.redirect_uris)),
                            created_at: Set(now.into()),
                            updated_at: Set(None),
                            ..Default::default()
                        }
                        .insert(txn)
                        .await?;
                    }

                    if !cors_origins.is_empty() {
                        client_openid_connect_cors_origin::Entity::insert_many(
                            cors_origins.into_iter().map(|origin| {
                                client_openid_connect_cors_origin::ActiveModel {
                                    client_id: Set(client_model.id),
                                    origin: Set(origin),
                                    created_at: Set(now.into()),
                                    updated_at: Set(None),
                                    ..Default::default()
                                }
                            }),
                        )
                        .exec(txn)
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

                    for credential in registration.credentials {
                        let expires_at = match &credential {
                            identity_domain::openid_connect::OpenIdConnectCredentialData::ClientSecret { .. } => {
                                (now + Duration::days(365)).into()
                            }
                            identity_domain::openid_connect::OpenIdConnectCredentialData::ClientPublicKey { .. } => {
                                non_expiring_timestamp()
                            }
                            identity_domain::openid_connect::OpenIdConnectCredentialData::ClientJsonWebKeySet { expires_at, .. } => {
                                (*expires_at).into()
                            }
                        };
                        let serialized = serialize_credential_data(credential);

                        client_openid_connect_credential::ActiveModel {
                            oid: Set(Uuid::new_v4()),
                            client_id: Set(client_model.id),
                            r#type: Set(serialized.type_),
                            data: Set(serialized.data),
                            hint: Set(serialized.hint),
                            expires_at: Set(expires_at),
                            revoked_at: Set(None),
                            created_at: Set(now.into()),
                            updated_at: Set(None),
                            ..Default::default()
                        }
                        .insert(txn)
                        .await?;
                    }

                    if update_auth.is_none() {
                    let registration_access_token = registration.registration_access_token;
                    client_authorization::ActiveModel {
                        oid: Set(Uuid::new_v4()),
                        client_id: Set(client_model.id),
                        r#type: Set(ClientAuthorizationType::RegistrationAccessToken.to_string()),
                        data: Set(serde_json::json!({ "token": registration_access_token })),
                        expires_at: Set((now + Duration::days(365)).into()),
                        completed_at: Set(None),
                        revoked_at: Set(None),
                        is_expired: Set(false),
                        created_at: Set(now.into()),
                        updated_at: Set(None),
                        ..Default::default()
                    }
                    .insert(txn)
                    .await?;

                    }
                    Ok(())
                })
            })
            .await
            .map_err(|error| {
                if error.to_string().contains("registration_invalid_token") {
                    return OpenIdConnectClientRepositoryError::ClientNotFound;
                }
                if error.to_string().contains("registration_invalid_secret") {
                    return OpenIdConnectClientRepositoryError::InvalidMetadataValue { field: "client_secret", value: String::new() };
                }
                OpenIdConnectClientRepositoryError::QueryFailed(Box::new(sea_orm::DbErr::Custom(
                    error.to_string(),
                )))
            })?;

        Ok(client_oid)
    }
}

#[async_trait]
impl OpenIdConnectClientRegistrationRepository for OpenIdConnectClientRepositoryImpl {
    async fn create(
        &self,
        registration: OpenIdConnectClientRegistration,
    ) -> Result<identity_domain::client::model::ClientOid, OpenIdConnectClientRepositoryError> {
        self.persist_registration(registration, None).await
    }

    async fn update(
        &self,
        registration: OpenIdConnectClientRegistration,
        token: &str,
        current_secret: Option<String>,
    ) -> Result<(), OpenIdConnectClientRepositoryError> {
        self.persist_registration(registration, Some((token.to_owned(), current_secret)))
            .await
            .map(|_| ())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_registration_access_token"))]
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
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(None);
        };

        let auth_rows = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::ClientId.eq(client_model.id))
            .filter(
                client_authorization::Column::Type
                    .eq(ClientAuthorizationType::RegistrationAccessToken.to_string()),
            )
            .filter(client_authorization::Column::RevokedAt.is_null())
            .filter(client_authorization::Column::ExpiresAt.gt(Utc::now()))
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        let valid = auth_rows.into_iter().any(|row| {
            row.data
                .get("token")
                .and_then(|value| value.as_str())
                .is_some_and(|stored| {
                    bool::from(subtle::ConstantTimeEq::ct_eq(
                        stored.as_bytes(),
                        token.as_bytes(),
                    ))
                })
        });

        if valid {
            self.find_by_oid(client_oid).await
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "delete_by_oid"))]
    async fn delete_by_oid(
        &self,
        client_oid: identity_domain::client::model::ClientOid,
    ) -> Result<(), OpenIdConnectClientRepositoryError> {
        let Some(client_model) = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .one(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Err(OpenIdConnectClientRepositoryError::ClientNotFound);
        };

        let result = ClientEntity::delete_many()
            .filter(client::Column::Id.eq(client_model.id))
            .filter(client::Column::BuiltIn.eq(false))
            .exec(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        if result.rows_affected == 0 {
            return Err(OpenIdConnectClientRepositoryError::BuiltInClient);
        }

        Ok(())
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for OpenIdConnectClientRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_oid"))]
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
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        let Some((client_model, metadata_model)) = row else {
            return Ok(None);
        };

        let Some(metadata_model) = metadata_model else {
            return Err(OpenIdConnectClientRepositoryError::MissingMetadata(oid));
        };

        let client_id = client_model.id;
        let platform_models = ClientOpenIdConnectPlatformEntity::find()
            .filter(client_openid_connect_platform::Column::ClientId.eq(client_id))
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;
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
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        let client = to_client(client_model)?;
        let metadata = to_metadata(metadata_model)?;
        Ok(Some(
            OpenIdConnectClient::new(client, metadata, platforms, assigned_scopes)
                .map_err(OpenIdConnectClientRepositoryError::InvalidClient)?,
        ))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_frontchannel_logout_clients_by_session_oid"))]
    async fn find_frontchannel_logout_clients_by_session_oid(
        &self,
        session_oid: SessionOid,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        self.find_logout_clients_by_session_oid(session_oid, LogoutChannel::Front)
            .await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_backchannel_logout_clients_by_session_oid"))]
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
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_logout_clients_by_session_oid"))]
    async fn find_logout_clients_by_session_oid(
        &self,
        session_oid: SessionOid,
        channel: LogoutChannel,
    ) -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let client_ids = LoginEntity::find()
            .inner_join(SessionEntity)
            .filter(session::Column::Oid.eq(Uuid::from(session_oid)))
            .select_only()
            .column(login::Column::ClientId)
            .distinct()
            .into_tuple::<i64>()
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        if client_ids.is_empty() {
            return Ok(Vec::new());
        }

        let channel_filter = match channel {
            LogoutChannel::Front => {
                client_openid_connect::Column::FrontchannelLogoutUri.is_not_null()
            }
            LogoutChannel::Back => {
                client_openid_connect::Column::BackchannelLogoutUri.is_not_null()
            }
        };
        let mut client_rows = ClientEntity::find()
            .filter(client::Column::Id.is_in(client_ids.clone()))
            .filter(client::Column::Protocol.eq("openid_connect"))
            .find_also_related(OpenIdConnectClientEntity)
            .filter(channel_filter)
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        if client_rows.is_empty() {
            return Ok(Vec::new());
        }

        client_rows.sort_by_key(|(client, _)| client.id);
        let matched_client_ids = client_rows
            .iter()
            .map(|(client, _)| client.id)
            .collect::<Vec<_>>();

        let platform_models = ClientOpenIdConnectPlatformEntity::find()
            .filter(
                client_openid_connect_platform::Column::ClientId.is_in(matched_client_ids.clone()),
            )
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;
        let mut platforms_by_client = std::collections::BTreeMap::<i64, Vec<_>>::new();
        for platform_model in platform_models {
            platforms_by_client
                .entry(platform_model.client_id)
                .or_default()
                .push(to_platform(platform_model)?);
        }

        let scope_rows = ClientScopeEntity::find()
            .inner_join(ScopeEntity)
            .filter(client_scope::Column::ClientId.is_in(matched_client_ids))
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .select_only()
            .column(client_scope::Column::ClientId)
            .column(scope::Column::Name)
            .into_tuple::<(i64, String)>()
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;
        let mut scopes_by_client = std::collections::BTreeMap::<i64, Vec<String>>::new();
        for (client_id, scope_name) in scope_rows {
            scopes_by_client
                .entry(client_id)
                .or_default()
                .push(scope_name);
        }

        let mut clients = Vec::with_capacity(client_rows.len());
        for (client_model, metadata_model) in client_rows {
            let metadata_model = metadata_model.ok_or(
                OpenIdConnectClientRepositoryError::MissingMetadata(client_model.oid),
            )?;
            let client_id = client_model.id;
            clients.push(
                OpenIdConnectClient::new(
                    to_client(client_model)?,
                    to_metadata(metadata_model)?,
                    platforms_by_client.remove(&client_id).unwrap_or_default(),
                    scopes_by_client.remove(&client_id).unwrap_or_default(),
                )
                .map_err(OpenIdConnectClientRepositoryError::InvalidClient)?,
            );
        }
        Ok(clients)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cors_origins_for_client, deserialize_optional_string_vec, parse_optional_url,
        parse_optional_urls, to_metadata, to_platform,
    };
    use crate::{
        domain::openid_connect::{
            OpenIdConnectClientPlatform, OpenIdConnectClientPlatformType,
            OpenIdConnectClientSettings,
        },
        infrastructure::database::entity::{client_openid_connect, client_openid_connect_platform},
    };
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn materialized_cors_origins_follow_client_settings_and_redirects() {
        let platforms = vec![
            OpenIdConnectClientPlatform {
                platform: OpenIdConnectClientPlatformType::Web,
                redirect_uris: [
                    "https://rp.example.com/callback",
                    "https://rp.example.com/another",
                    "http://localhost:3000/callback",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            },
            OpenIdConnectClientPlatform {
                platform: OpenIdConnectClientPlatformType::Native,
                redirect_uris: vec!["com.example.app:/callback".to_owned()],
            },
        ];
        let mut settings = OpenIdConnectClientSettings::default();
        assert!(cors_origins_for_client(&settings, &platforms).is_empty());

        settings.cors_enabled = true;
        assert_eq!(
            cors_origins_for_client(&settings, &platforms),
            ["http://localhost:3000", "https://rp.example.com"]
        );
    }

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
    fn maps_logout_and_multivalue_metadata() {
        let metadata = to_metadata(client_openid_connect::Model {
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
            id_token_signed_response_algs: Some(json!(["RS256", "ES256"])),
            id_token_encrypted_response_algs: None,
            id_token_encrypted_response_encs: None,
            userinfo_signed_response_algs: None,
            userinfo_encrypted_response_algs: None,
            userinfo_encrypted_response_encs: None,
            request_object_signing_algs: None,
            request_object_encryption_algs: None,
            request_object_encryption_encs: None,
            token_endpoint_auth_methods: Some(json!(["client_secret_basic", "none"])),
            token_endpoint_auth_signing_algs: None,
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
        assert_eq!(
            metadata
                .id_token_signed_response_algs
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["RS256", "ES256"]
        );
        assert_eq!(
            metadata
                .token_endpoint_auth_methods
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["client_secret_basic", "none"]
        );
    }

    #[test]
    fn maps_client_openid_connect_platform_redirect_uris() {
        let platform = to_platform(client_openid_connect_platform::Model {
            id: 1,
            client_id: 2,
            platform: "web".to_string(),
            redirect_uris: Some(json!(["http://localhost:53000"])),
            created_at: Utc::now().into(),
            updated_at: None,
        })
        .unwrap();

        assert_eq!(platform.platform, OpenIdConnectClientPlatformType::Web);
        assert_eq!(platform.redirect_uris[0], "http://localhost:53000");
    }

    #[test]
    fn rejects_unknown_client_openid_connect_platform() {
        let error = to_platform(client_openid_connect_platform::Model {
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
#[cfg(test)]
mod registration_update_tests {
    use super::*;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    fn registration(oid: Uuid) -> OpenIdConnectClientRegistration {
        OpenIdConnectClientRegistration {
            client: Client {
                oid,
                protocol: identity_domain::client::model::ClientProtocol::OpenIdConnect,
                name: "Updated".into(),
                names: vec![],
                description: None,
                built_in: false,
                created_at: Utc::now(),
                updated_at: Some(Utc::now()),
            },
            metadata: OpenIdConnectClientMetadata::default(),
            platforms: vec![],
            assigned_scopes: vec![],
            credentials: vec![],
            registration_access_token: "rat".into(),
        }
    }

    fn client_row(oid: Uuid) -> client::Model {
        client::Model {
            id: 1,
            oid,
            protocol: "openid_connect".into(),
            name: "Old".into(),
            names: None,
            description: None,
            built_in: false,
            created_at: Utc::now().into(),
            updated_at: None,
        }
    }

    fn metadata_row() -> client_openid_connect::Model {
        use serde_json::json;
        client_openid_connect::Model {
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
            id_token_signed_response_algs: Some(json!(["RS256", "ES256"])),
            id_token_encrypted_response_algs: None,
            id_token_encrypted_response_encs: None,
            userinfo_signed_response_algs: None,
            userinfo_encrypted_response_algs: None,
            userinfo_encrypted_response_encs: None,
            request_object_signing_algs: None,
            request_object_encryption_algs: None,
            request_object_encryption_encs: None,
            token_endpoint_auth_methods: Some(json!(["client_secret_basic", "none"])),
            token_endpoint_auth_signing_algs: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            settings: json!({}),
            created_at: Utc::now().into(),
            updated_at: None,
        }
    }

    fn auth_row() -> client_authorization::Model {
        client_authorization::Model {
            id: 1,
            oid: Uuid::new_v4(),
            client_id: 1,
            r#type: "registration_access_token".into(),
            data: serde_json::json!({"token":"rat"}),
            expires_at: (Utc::now() + Duration::days(1)).into(),
            completed_at: None,
            revoked_at: None,
            is_expired: false,
            created_at: Utc::now().into(),
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn update_rechecks_token_and_secret_before_mutation() {
        let oid = Uuid::new_v4();
        for (token, secret) in [("wrong", None), ("rat", Some("chosen-secret".to_owned()))] {
            let db = MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results([vec![client_row(oid)]])
                .append_query_results([vec![auth_row()]])
                .append_query_results([Vec::<client_openid_connect_credential::Model>::new()])
                .into_connection();
            let repo = OpenIdConnectClientRepositoryImpl::new(db.clone());
            let error = repo
                .update(registration(oid), token, secret)
                .await
                .unwrap_err();
            if token == "wrong" {
                assert!(matches!(
                    error,
                    OpenIdConnectClientRepositoryError::ClientNotFound
                ));
            } else {
                assert!(matches!(
                    error,
                    OpenIdConnectClientRepositoryError::InvalidMetadataValue {
                        field: "client_secret",
                        ..
                    }
                ));
            }
            let log = format!("{:?}", db.into_transaction_log());
            assert!(log.contains("FOR UPDATE"), "{log}");
            assert!(log.contains("ROLLBACK"), "{log}");
            assert!(!log.contains("DELETE"), "{log}");
        }
    }

    #[tokio::test]
    async fn update_replaces_metadata_in_one_transaction_without_deleting_grants() {
        let oid = Uuid::new_v4();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![client_row(oid)]])
            .append_query_results([vec![auth_row()]])
            .append_query_results([vec![client_row(oid)]])
            .append_query_results([vec![metadata_row()]])
            .append_exec_results((0..5).map(|_| MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }))
            .into_connection();
        let repo = OpenIdConnectClientRepositoryImpl::new(db.clone());
        repo.update(registration(oid), "rat", None).await.unwrap();
        let log = format!("{:?}", db.into_transaction_log());
        assert!(log.contains("COMMIT"), "{log}");
        assert!(log.contains(r#"UPDATE \"client\""#), "{log}");
        assert!(!log.contains(r#"DELETE FROM \"client\""#), "{log}");
        assert!(
            !log.contains(r#"DELETE FROM \"client_authorization\""#),
            "{log}"
        );
        assert!(
            !log.contains(r#"INSERT INTO \"client_authorization\""#),
            "{log}"
        );
    }
}
