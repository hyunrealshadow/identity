use super::OpenIdConnectClientRepositoryImpl;
use crate::database::{
    audit, client_authorization_boundary,
    entity::{
        client,
        client::{Column as ClientColumn, Entity as ClientEntity},
        client_authorization,
        client_authorization::{
            Column as ClientAuthorizationColumn, Entity as ClientAuthorizationEntity,
        },
        client_openid_connect,
        client_openid_connect::{
            Column as ClientOpenIdConnectColumn, Entity as OpenIdConnectClientEntity,
        },
        client_openid_connect_cors_origin,
        client_openid_connect_cors_origin::{
            Column as ClientOpenIdConnectCorsOriginColumn,
            Entity as ClientOpenIdConnectCorsOriginEntity,
        },
        client_openid_connect_credential,
        client_openid_connect_credential::{
            Column as ClientOpenIdConnectCredentialColumn,
            Entity as ClientOpenIdConnectCredentialEntity,
        },
        client_openid_connect_platform,
        client_openid_connect_platform::{
            Column as ClientOpenIdConnectPlatformColumn,
            Entity as ClientOpenIdConnectPlatformEntity,
        },
        client_scope,
        resource::{Column as ResourceColumn, Entity as ResourceEntity},
        scope::{Column as ScopeColumn, Entity as ScopeEntity},
    },
    repository::{
        openid_connect_credential::serialize_data as serialize_credential_data,
        shared::non_expiring_timestamp,
    },
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use identity_domain::{
    authorization::catalog,
    client::model::ClientOid,
    client_authorization::ClientAuthorizationType,
    openid_connect::{
        API_RESOURCE, OpenIdConnectClient, OpenIdConnectClientPlatform,
        OpenIdConnectClientRegistration, OpenIdConnectClientRegistrationRepository,
        OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
        OpenIdConnectClientSettings, OpenIdConnectCredentialData,
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DbErr, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, Set, TransactionTrait,
};
use serde_json::{Value, json, to_value};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

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

pub(super) fn cors_origins_for_client(
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
    ) -> Result<ClientOid, OpenIdConnectClientRepositoryError> {
        let client_oid = registration.client.oid;
        let now = Utc::now();
        let cors_origins =
            cors_origins_for_client(&registration.metadata.settings, &registration.platforms);

        self.db
            .transaction::<_, _, DbErr>(|txn| {
                Box::pin(async move {
                    if update_auth.is_none()
                        && registration
                            .assigned_scopes
                            .iter()
                            .any(|scope| catalog::is_reserved_management_name(scope))
                    {
                        return Err(DbErr::Custom("registration_invalid_scope".into()));
                    }
                    let existing = if let Some((token, secret)) = &update_auth {
                        let existing = ClientEntity::find()
                            .filter(ClientColumn::Oid.eq(client_oid))
                            .lock_exclusive()
                            .one(txn)
                            .await?
                            .ok_or_else(|| DbErr::Custom("registration_invalid_token".into()))?;
                        if existing.built_in {
                            return Err(DbErr::Custom("registration_invalid_token".into()));
                        }
                        let rows =
                            ClientAuthorizationEntity::find()
                                .filter(ClientAuthorizationColumn::ClientId.eq(existing.id))
                                .filter(ClientAuthorizationColumn::Type.eq(
                                    ClientAuthorizationType::RegistrationAccessToken.to_string(),
                                ))
                                .filter(ClientAuthorizationColumn::RevokedAt.is_null())
                                .filter(ClientAuthorizationColumn::ExpiresAt.gt(now))
                                .all(txn)
                                .await?;
                        let valid = rows.iter().any(|row| {
                            row.data
                                .get("token")
                                .and_then(Value::as_str)
                                .is_some_and(|stored| {
                                    bool::from(ConstantTimeEq::ct_eq(
                                        stored.as_bytes(),
                                        token.as_bytes(),
                                    ))
                                })
                        });
                        if !valid {
                            return Err(DbErr::Custom("registration_invalid_token".into()));
                        }
                        if let Some(secret) = secret {
                            let rows = ClientOpenIdConnectCredentialEntity::find()
                                .filter(
                                    ClientOpenIdConnectCredentialColumn::ClientId.eq(existing.id),
                                )
                                .filter(
                                    ClientOpenIdConnectCredentialColumn::Type.eq("client_secret"),
                                )
                                .filter(ClientOpenIdConnectCredentialColumn::RevokedAt.is_null())
                                .filter(ClientOpenIdConnectCredentialColumn::ExpiresAt.gt(now))
                                .all(txn)
                                .await?;
                            let valid = rows.iter().any(|row| {
                                row.data.get("secret").and_then(Value::as_str).is_some_and(
                                    |stored| {
                                        bool::from(ConstantTimeEq::ct_eq(
                                            stored.as_bytes(),
                                            secret.as_bytes(),
                                        ))
                                    },
                                )
                            });
                            if !valid {
                                return Err(DbErr::Custom("registration_invalid_secret".into()));
                            }
                        }
                        let metadata = OpenIdConnectClientEntity::find()
                            .filter(ClientOpenIdConnectColumn::ClientId.eq(existing.id))
                            .lock_exclusive()
                            .one(txn)
                            .await?
                            .ok_or_else(|| DbErr::Custom("registration_metadata_missing".into()))?;
                        Some((existing, metadata))
                    } else {
                        None
                    };
                    let mut existing_credentials = if let Some((client_model, _)) = &existing {
                        ClientOpenIdConnectCredentialEntity::find()
                            .filter(
                                ClientOpenIdConnectCredentialColumn::ClientId.eq(client_model.id),
                            )
                            .order_by_asc(ClientOpenIdConnectCredentialColumn::Id)
                            .all(txn)
                            .await?
                    } else {
                        Vec::new()
                    };
                    // Capture the authority boundary before any of the update
                    // writes. Display-only edits must not advance it.
                    let before_fingerprint = if let Some((client_model, _)) = &existing {
                        Some(
                            client_authorization_boundary::client_boundary_fingerprint(
                                txn,
                                client_model.id,
                            )
                            .await?,
                        )
                    } else {
                        None
                    };
                    let client_model = client::ActiveModel {
                        id: existing
                            .as_ref()
                            .map(|(model, _)| Set(model.id))
                            .unwrap_or_default(),
                        oid: Set(registration.client.oid),
                        protocol: Set(registration.client.protocol.to_string()),
                        name: Set(registration.client.name),
                        names: Set(optional_strings_to_json(Some(registration.client.names))),
                        description: Set(registration.client.description),
                        descriptions: Default::default(),
                        built_in: Set(registration.client.built_in),
                        version: Set(Uuid::new_v4()),
                        created_at: Set(registration.client.created_at.into()),
                        updated_at: Set(registration.client.updated_at.map(Into::into)),
                    };
                    let client_model = if existing.is_some() {
                        client_model.update(txn).await?
                    } else {
                        client_model.insert(txn).await?
                    };

                    let metadata = registration.metadata;
                    let settings = to_value(metadata.settings)
                        .map_err(|error| DbErr::Custom(error.to_string()))?;
                    let existing_metadata = existing.as_ref().map(|(_, metadata)| metadata);
                    let metadata_model = client_openid_connect::ActiveModel {
                        id: existing_metadata
                            .map(|metadata| Set(metadata.id))
                            .unwrap_or_default(),
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
                            |values| values.into_iter().map(|value| value.to_string()).collect(),
                        ))),
                        grant_types: Set(optional_strings_to_json(metadata.grant_types.map(
                            |values| values.into_iter().map(|value| value.to_string()).collect(),
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
                        id_token_signed_response_algs: Set(optional_metadata_values_to_json(
                            metadata.id_token_signed_response_algs,
                        )),
                        id_token_encrypted_response_algs: Set(optional_metadata_values_to_json(
                            metadata.id_token_encrypted_response_algs,
                        )),
                        id_token_encrypted_response_encs: Set(optional_metadata_values_to_json(
                            metadata.id_token_encrypted_response_encs,
                        )),
                        userinfo_signed_response_algs: Set(optional_metadata_values_to_json(
                            metadata.userinfo_signed_response_algs,
                        )),
                        userinfo_encrypted_response_algs: Set(optional_metadata_values_to_json(
                            metadata.userinfo_encrypted_response_algs,
                        )),
                        userinfo_encrypted_response_encs: Set(optional_metadata_values_to_json(
                            metadata.userinfo_encrypted_response_encs,
                        )),
                        request_object_signing_algs: Set(optional_metadata_values_to_json(
                            metadata.request_object_signing_algs,
                        )),
                        request_object_encryption_algs: Set(optional_metadata_values_to_json(
                            metadata.request_object_encryption_algs,
                        )),
                        request_object_encryption_encs: Set(optional_metadata_values_to_json(
                            metadata.request_object_encryption_encs,
                        )),
                        token_endpoint_auth_methods: Set(optional_metadata_values_to_json(
                            metadata.token_endpoint_auth_methods,
                        )),
                        token_endpoint_auth_signing_algs: Set(optional_metadata_values_to_json(
                            metadata.token_endpoint_auth_signing_algs,
                        )),
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
                        created_at: match existing_metadata {
                            Some(metadata) => Set(metadata.created_at),
                            None => Set(now.into()),
                        },
                        updated_at: match existing_metadata {
                            Some(_) => Set(Some(now.into())),
                            None => Set(None),
                        },
                    };
                    if existing_metadata.is_some() {
                        metadata_model.update(txn).await?;
                    } else {
                        metadata_model.insert(txn).await?;
                    }

                    if existing.is_some() {
                        ClientOpenIdConnectPlatformEntity::delete_many()
                            .filter(ClientOpenIdConnectPlatformColumn::ClientId.eq(client_model.id))
                            .exec(txn)
                            .await?;
                        ClientOpenIdConnectCorsOriginEntity::delete_many()
                            .filter(
                                ClientOpenIdConnectCorsOriginColumn::ClientId.eq(client_model.id),
                            )
                            .exec(txn)
                            .await?;
                    }

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
                        ClientOpenIdConnectCorsOriginEntity::insert_many(
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

                    if existing.is_none() && !registration.assigned_scopes.is_empty() {
                        let scope_models = ScopeEntity::find()
                            .filter(
                                ScopeColumn::Code
                                    .is_in(registration.assigned_scopes.iter().cloned()),
                            )
                            .filter(ScopeColumn::Enabled.eq(true))
                            .filter(ScopeColumn::BuiltIn.eq(true))
                            .filter(
                                Condition::any().add(ScopeColumn::ResourceId.is_null()).add(
                                    Condition::all()
                                        .add(ScopeColumn::Code.is_in([
                                            "account.read",
                                            "account.update",
                                            "session.read",
                                            "session.revoke",
                                            "password.change",
                                        ]))
                                        .add(
                                            ScopeColumn::ResourceId.in_subquery(
                                                ResourceEntity::find()
                                                    .select_only()
                                                    .column(ResourceColumn::Oid)
                                                    .filter(ResourceColumn::Uri.eq(API_RESOURCE))
                                                    .into_query(),
                                            ),
                                        ),
                                ),
                            )
                            .all(txn)
                            .await?;
                        let expected = registration
                            .assigned_scopes
                            .iter()
                            .collect::<BTreeSet<_>>()
                            .len();
                        if scope_models.len() != expected {
                            return Err(DbErr::Custom("registration_invalid_scope".into()));
                        }
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
                            OpenIdConnectCredentialData::ClientSecret { .. } => {
                                (now + Duration::days(365)).into()
                            }
                            OpenIdConnectCredentialData::ClientPublicKey { .. } => {
                                non_expiring_timestamp()
                            }
                            OpenIdConnectCredentialData::ClientJsonWebKeySet {
                                expires_at, ..
                            } => (*expires_at).into(),
                        };
                        let serialized = serialize_credential_data(credential);

                        // Credential identity and expiry are part of the
                        // authority boundary. Re-submitting the exact same
                        // type and data keeps the existing row untouched,
                        // including a revoked tombstone; never reset a same
                        // secret's expiry or revive it through a new row.
                        if let Some(position) = existing_credentials.iter().position(|row| {
                            row.r#type == serialized.type_ && row.data == serialized.data
                        }) {
                            existing_credentials.remove(position);
                            continue;
                        }

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
                    if !existing_credentials.is_empty() {
                        let removed_ids = existing_credentials
                            .into_iter()
                            .map(|credential| credential.id)
                            .collect::<Vec<_>>();
                        ClientOpenIdConnectCredentialEntity::delete_many()
                            .filter(ClientOpenIdConnectCredentialColumn::Id.is_in(removed_ids))
                            .exec(txn)
                            .await?;
                    }

                    // The registration control-plane token belongs to the
                    // update endpoint itself and is never replaced on update.
                    if update_auth.is_none() {
                        let registration_access_token = registration.registration_access_token;
                        client_authorization::ActiveModel {
                            oid: Set(Uuid::new_v4()),
                            client_id: Set(client_model.id),
                            r#type: Set(
                                ClientAuthorizationType::RegistrationAccessToken.to_string()
                            ),
                            data: Set(json!({ "token": registration_access_token })),
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

                    // Only a real change to the issuance boundary withdraws
                    // existing artifacts. A metadata-only write renews the
                    // public record version without advancing authority.
                    if let (Some(before), Some((target, _))) =
                        (before_fingerprint, existing.as_ref())
                    {
                        let after = client_authorization_boundary::client_boundary_fingerprint(
                            txn, target.id,
                        )
                        .await?;
                        if after.1 != before.1 {
                            client_authorization_boundary::withdraw_on_boundary_change(
                                txn, target.id,
                            )
                            .await?;
                        }
                    }
                    audit::record(
                        txn,
                        if update_auth.is_some() {
                            "client.registration.update"
                        } else {
                            "client.registration.create"
                        },
                        "client",
                        client_oid,
                    )
                    .await?;
                    Ok(())
                })
            })
            .await
            .map_err(|error| {
                if error.to_string().contains("registration_invalid_token") {
                    return OpenIdConnectClientRepositoryError::ClientNotFound;
                }
                if error.to_string().contains("registration_invalid_scope") {
                    return OpenIdConnectClientRepositoryError::InvalidMetadataValue {
                        field: "scope",
                        value: String::new(),
                    };
                }
                if error.to_string().contains("registration_invalid_secret") {
                    return OpenIdConnectClientRepositoryError::InvalidMetadataValue {
                        field: "client_secret",
                        value: String::new(),
                    };
                }
                if error.to_string().contains("registration_metadata_missing") {
                    return OpenIdConnectClientRepositoryError::MissingMetadata(client_oid);
                }
                OpenIdConnectClientRepositoryError::QueryFailed(Box::new(DbErr::Custom(
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
    ) -> Result<ClientOid, OpenIdConnectClientRepositoryError> {
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
        client_oid: ClientOid,
        token: &str,
    ) -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError> {
        let Some(client_model) = ClientEntity::find()
            .filter(ClientColumn::Oid.eq(client_oid))
            .filter(ClientColumn::Protocol.eq("openid_connect"))
            .one(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(None);
        };

        let auth_rows = ClientAuthorizationEntity::find()
            .filter(ClientAuthorizationColumn::ClientId.eq(client_model.id))
            .filter(
                ClientAuthorizationColumn::Type
                    .eq(ClientAuthorizationType::RegistrationAccessToken.to_string()),
            )
            .filter(ClientAuthorizationColumn::RevokedAt.is_null())
            .filter(ClientAuthorizationColumn::ExpiresAt.gt(Utc::now()))
            .all(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        let valid = auth_rows.into_iter().any(|row| {
            row.data
                .get("token")
                .and_then(|value| value.as_str())
                .is_some_and(|stored| {
                    bool::from(ConstantTimeEq::ct_eq(stored.as_bytes(), token.as_bytes()))
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
        client_oid: ClientOid,
    ) -> Result<(), OpenIdConnectClientRepositoryError> {
        let Some(client_model) = ClientEntity::find()
            .filter(ClientColumn::Oid.eq(client_oid))
            .filter(ClientColumn::Protocol.eq("openid_connect"))
            .one(&self.db)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Err(OpenIdConnectClientRepositoryError::ClientNotFound);
        };

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;
        let result = ClientEntity::delete_many()
            .filter(ClientColumn::Id.eq(client_model.id))
            .filter(ClientColumn::BuiltIn.eq(false))
            .exec(&txn)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        if result.rows_affected == 0 {
            return Err(OpenIdConnectClientRepositoryError::BuiltInClient);
        }

        audit::record(&txn, "client.registration.delete", "client", client_oid)
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;
        txn.commit()
            .await
            .map_err(|e| OpenIdConnectClientRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(())
    }
}
