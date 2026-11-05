//! Client management writes.
//!
//! Each write re-checks management authority on authoritative rows, locks the
//! client row, compares its UUID version, protects built-in clients, permanently
//! withdraws issued artifacts when the client's authorization boundary really
//! changes, replaces the version and appends the semantic audit fact before
//! committing. Display text never participates in the boundary, so profile edits
//! do not invalidate grants.

use chrono::{Duration, Utc};
use identity_application::{
    client::{
        ClientCredentialRecord, ClientCredentialRevokeResult, ClientEntityKind,
        ClientManagementRepositoryError, ClientProtocolSettings, ClientRecord, ClientSecretResult,
        ClientStateTransaction, CreateClientSecretTransaction, CreateClientTransaction,
        IssuedClientSecret, RevokeClientCredentialTransaction, UpdateClientTransaction,
    },
    rbac::RbacManagementAuthority,
};
use identity_domain::{
    authorization::{ManagementScope, PolicyVersion},
    client::model::ClientOid,
    openid_connect::{
        GrantType, OpenIdConnectClientPlatform, OpenIdConnectClientSettings,
        OpenIdConnectCredentialOid, OpenIdConnectCredentialType, TokenEndpointAuthMethod,
    },
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    ModelTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};
use serde_json::{Value, from_value, json, to_value};
use uuid::Uuid;

use super::{
    read::{PROTOCOL, credential_record, find_record},
    support::{corrupt, from_management, storage},
};
use crate::database::{
    client_authorization_boundary::{client_boundary_fingerprint, withdraw_client_authorizations},
    entity::{
        client,
        client::{Column as ClientColumn, Entity as ClientEntity},
        client_openid_connect,
        client_openid_connect::{Column as OpenIdConnectColumn, Entity as OpenIdConnectEntity},
        client_openid_connect_cors_origin,
        client_openid_connect_cors_origin::{
            Column as CorsOriginColumn, Entity as CorsOriginEntity,
        },
        client_openid_connect_credential,
        client_openid_connect_credential::{
            Column as CredentialColumn, Entity as CredentialEntity,
        },
        client_openid_connect_platform,
        client_openid_connect_platform::{Column as PlatformColumn, Entity as PlatformEntity},
        client_scope,
        scope::{Column as ScopeColumn, Entity as ScopeEntity},
    },
    repository::{
        localized,
        openid_connect::registration::cors_origins_for_client,
        openid_connect_credential::serialize_data,
        rbac_management::{audit::append_semantic_audit, authority::recheck_authority},
    },
};

const AUDIT_TARGET: &str = "client";

async fn begin(
    db: &DatabaseConnection,
    authority: &RbacManagementAuthority,
    required: ManagementScope,
) -> Result<DatabaseTransaction, ClientManagementRepositoryError> {
    let txn = db.begin().await.map_err(storage)?;
    recheck_authority(&txn, authority, required, None)
        .await
        .map_err(from_management)?;
    Ok(txn)
}

/// Lock one managed client for a write and enforce its optimistic lock.
async fn lock_client(
    txn: &DatabaseTransaction,
    oid: ClientOid,
    expected_version: Uuid,
) -> Result<client::Model, ClientManagementRepositoryError> {
    let model = ClientEntity::find()
        .filter(ClientColumn::Oid.eq(oid))
        .filter(ClientColumn::Protocol.eq(PROTOCOL))
        .lock_exclusive()
        .one(txn)
        .await
        .map_err(storage)?
        .ok_or(ClientManagementRepositoryError::NotFound(
            ClientEntityKind::Client,
        ))?;
    if model.built_in {
        return Err(ClientManagementRepositoryError::BuiltInProtected);
    }
    if model.version != expected_version {
        return Err(ClientManagementRepositoryError::VersionConflict {
            current_version: model.version,
        });
    }
    Ok(model)
}

async fn boundary(
    txn: &DatabaseTransaction,
    client_id: i64,
) -> Result<PolicyVersion, ClientManagementRepositoryError> {
    client_boundary_fingerprint(txn, client_id)
        .await
        .map(|(_, fingerprint)| fingerprint)
        .map_err(storage)
}

/// Replace the version, withdraw issued artifacts when required, audit and
/// commit.
#[allow(clippy::too_many_arguments)]
async fn finish(
    txn: DatabaseTransaction,
    model: client::Model,
    withdraw: bool,
    action: &'static str,
    authority: &RbacManagementAuthority,
    reason: &str,
) -> Result<(), ClientManagementRepositoryError> {
    let client_id = model.id;
    let oid = model.oid;
    let mut active: client::ActiveModel = model.into();
    active.version = Set(Uuid::new_v4());
    active.updated_at = Set(Some(Utc::now().into()));
    active.update(&txn).await.map_err(storage)?;
    if withdraw {
        withdraw_client_authorizations(&txn, client_id)
            .await
            .map_err(storage)?;
    }
    append_semantic_audit(&txn, authority, action, AUDIT_TARGET, oid, reason)
        .await
        .map_err(from_management)?;
    txn.commit().await.map_err(storage)
}

async fn reload(
    db: &DatabaseConnection,
    oid: ClientOid,
) -> Result<ClientRecord, ClientManagementRepositoryError> {
    find_record(db, oid).await?.ok_or_else(corrupt)
}

fn grant_types_json(grants: &[GrantType]) -> Value {
    Value::Array(grants.iter().map(|grant| json!(grant.as_str())).collect())
}

/// Persist the protocol configuration, keeping settings this surface does not
/// edit (OAuth version, scoped-claim options) as they are.
async fn write_protocol(
    txn: &DatabaseTransaction,
    client_id: i64,
    settings: &ClientProtocolSettings,
) -> Result<(), ClientManagementRepositoryError> {
    let now = Utc::now();
    let existing = OpenIdConnectEntity::find()
        .filter(OpenIdConnectColumn::ClientId.eq(client_id))
        .one(txn)
        .await
        .map_err(storage)?;
    let mut stored = match &existing {
        Some(row) => from_value::<OpenIdConnectClientSettings>(row.settings.clone())
            .map_err(|_| corrupt())?,
        None => OpenIdConnectClientSettings::default(),
    };
    stored.require_pushed_authorization_requests = settings.require_pushed_authorization_requests;
    stored.skip_consent = settings.skip_consent;
    stored.cors_enabled = settings.cors_enabled;
    stored.allow_public_client_flow =
        settings.token_endpoint_auth_method == TokenEndpointAuthMethod::None;
    let stored_json = to_value(&stored).map_err(|_| corrupt())?;
    let response_types = if settings.grant_types.contains(&GrantType::AuthorizationCode) {
        json!(["code"])
    } else {
        json!([])
    };
    let post_logout = json!(settings.post_logout_redirect_uris);
    let methods = json!([settings.token_endpoint_auth_method.to_string()]);
    match existing {
        Some(row) => {
            let mut active: client_openid_connect::ActiveModel = row.into();
            active.grant_types = Set(Some(grant_types_json(&settings.grant_types)));
            active.response_types = Set(Some(response_types));
            active.token_endpoint_auth_methods = Set(Some(methods));
            active.post_logout_redirect_uris = Set(Some(post_logout));
            active.settings = Set(stored_json);
            active.updated_at = Set(Some(now.into()));
            active.update(txn).await.map_err(storage)?;
        }
        None => {
            client_openid_connect::ActiveModel {
                client_id: Set(client_id),
                grant_types: Set(Some(grant_types_json(&settings.grant_types))),
                response_types: Set(Some(response_types)),
                token_endpoint_auth_methods: Set(Some(methods)),
                post_logout_redirect_uris: Set(Some(post_logout)),
                settings: Set(stored_json),
                created_at: Set(now.into()),
                ..Default::default()
            }
            .insert(txn)
            .await
            .map_err(storage)?;
        }
    }

    PlatformEntity::delete_many()
        .filter(PlatformColumn::ClientId.eq(client_id))
        .exec(txn)
        .await
        .map_err(storage)?;
    let mut platforms = Vec::with_capacity(settings.platforms.len());
    for platform in &settings.platforms {
        client_openid_connect_platform::ActiveModel {
            client_id: Set(client_id),
            platform: Set(platform.platform.to_string()),
            redirect_uris: Set(Some(json!(platform.redirect_uris))),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(txn)
        .await
        .map_err(storage)?;
        platforms.push(OpenIdConnectClientPlatform {
            platform: platform.platform.clone(),
            redirect_uris: platform.redirect_uris.clone(),
        });
    }

    CorsOriginEntity::delete_many()
        .filter(CorsOriginColumn::ClientId.eq(client_id))
        .exec(txn)
        .await
        .map_err(storage)?;
    for origin in cors_origins_for_client(&stored, &platforms) {
        client_openid_connect_cors_origin::ActiveModel {
            client_id: Set(client_id),
            origin: Set(origin),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(txn)
        .await
        .map_err(storage)?;
    }
    Ok(())
}

pub(super) async fn create(
    db: &DatabaseConnection,
    command: CreateClientTransaction,
) -> Result<ClientRecord, ClientManagementRepositoryError> {
    let txn = begin(db, &command.authority, ManagementScope::ClientsCreate).await?;
    let model = client::ActiveModel {
        oid: Set(command.client_oid),
        protocol: Set(PROTOCOL.to_owned()),
        name: Set(command.name),
        names: Set(Some(localized::encode_text(&command.names))),
        description: Set((!command.description.is_empty()).then_some(command.description)),
        descriptions: Set(Some(localized::encode_text(&command.descriptions))),
        built_in: Set(false),
        enabled: Set(true),
        version: Set(Uuid::new_v4()),
        created_at: Set(Utc::now().into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(storage)?;
    write_protocol(&txn, model.id, &command.settings).await?;
    assign_default_protocol_scopes(&txn, model.id, &command.settings).await?;
    append_semantic_audit(
        &txn,
        &command.authority,
        "client.create",
        AUDIT_TARGET,
        command.client_oid,
        &command.reason,
    )
    .await
    .map_err(from_management)?;
    txn.commit().await.map_err(storage)?;
    reload(db, command.client_oid).await
}

/// Protocol scopes a new interactive client starts with: sign-in identity and
/// basic claims, plus `offline_access` when it may use refresh tokens. Machine
/// clients start with none. Administrators adjust the set on the scopes page.
fn default_protocol_scope_codes(settings: &ClientProtocolSettings) -> Vec<&'static str> {
    let grants = &settings.grant_types;
    let interactive =
        grants.contains(&GrantType::AuthorizationCode) || grants.contains(&GrantType::DeviceCode);
    if !interactive {
        return Vec::new();
    }
    let mut codes = vec!["openid", "profile", "email"];
    if grants.contains(&GrantType::RefreshToken) {
        codes.push("offline_access");
    }
    codes
}

async fn assign_default_protocol_scopes(
    txn: &DatabaseTransaction,
    client_id: i64,
    settings: &ClientProtocolSettings,
) -> Result<(), ClientManagementRepositoryError> {
    let codes = default_protocol_scope_codes(settings);
    if codes.is_empty() {
        return Ok(());
    }
    let scopes = ScopeEntity::find()
        .filter(ScopeColumn::Code.is_in(codes))
        .filter(ScopeColumn::ResourceId.is_null())
        .filter(ScopeColumn::BuiltIn.eq(true))
        .filter(ScopeColumn::Enabled.eq(true))
        .all(txn)
        .await
        .map_err(storage)?;
    for scope in scopes {
        client_scope::ActiveModel {
            client_id: Set(client_id),
            scope_id: Set(scope.id),
            client_granted: Set(false),
            created_at: Set(Utc::now().into()),
            ..Default::default()
        }
        .insert(txn)
        .await
        .map_err(storage)?;
    }
    Ok(())
}

pub(super) async fn update(
    db: &DatabaseConnection,
    command: UpdateClientTransaction,
) -> Result<ClientRecord, ClientManagementRepositoryError> {
    let txn = begin(db, &command.authority, ManagementScope::ClientsUpdate).await?;
    let model = lock_client(&txn, command.client_oid, command.expected_version).await?;
    let before = boundary(&txn, model.id).await?;
    let mut active: client::ActiveModel = model.clone().into();
    if let Some(name) = command.name {
        active.name = Set(name);
    }
    if let Some(description) = command.description {
        active.description = Set((!description.is_empty()).then_some(description));
    }
    if let Some(names) = &command.names {
        active.names = Set(Some(localized::encode_text(names)));
    }
    if let Some(descriptions) = &command.descriptions {
        active.descriptions = Set(Some(localized::encode_text(descriptions)));
    }
    let model = active.update(&txn).await.map_err(storage)?;
    if let Some(settings) = &command.settings {
        write_protocol(&txn, model.id, settings).await?;
    }
    let changed = boundary(&txn, model.id).await? != before;
    finish(
        txn,
        model,
        changed,
        "client.update",
        &command.authority,
        &command.reason,
    )
    .await?;
    reload(db, command.client_oid).await
}

pub(super) async fn set_enabled(
    db: &DatabaseConnection,
    command: ClientStateTransaction,
    enabled: bool,
) -> Result<ClientRecord, ClientManagementRepositoryError> {
    let txn = begin(db, &command.authority, ManagementScope::ClientsState).await?;
    let model = lock_client(&txn, command.client_oid, command.expected_version).await?;
    if model.enabled == enabled {
        txn.commit().await.map_err(storage)?;
        return reload(db, command.client_oid).await;
    }
    let mut active: client::ActiveModel = model.into();
    active.enabled = Set(enabled);
    let model = active.update(&txn).await.map_err(storage)?;
    // Disabling withdraws permanently; enabling never revives withdrawn
    // artifacts.
    finish(
        txn,
        model,
        !enabled,
        if enabled {
            "client.enable"
        } else {
            "client.disable"
        },
        &command.authority,
        &command.reason,
    )
    .await?;
    reload(db, command.client_oid).await
}

pub(super) async fn delete(
    db: &DatabaseConnection,
    command: ClientStateTransaction,
) -> Result<ClientOid, ClientManagementRepositoryError> {
    let txn = begin(db, &command.authority, ManagementScope::ClientsDelete).await?;
    let model = lock_client(&txn, command.client_oid, command.expected_version).await?;
    // Protocol configuration, platforms, origins, credentials, scope
    // assignments, consents and issued artifacts are removed by cascade.
    model.delete(&txn).await.map_err(storage)?;
    append_semantic_audit(
        &txn,
        &command.authority,
        "client.delete",
        AUDIT_TARGET,
        command.client_oid,
        &command.reason,
    )
    .await
    .map_err(from_management)?;
    txn.commit().await.map_err(storage)?;
    Ok(command.client_oid)
}

/// Lock one credential of the client for revocation.
async fn lock_credential(
    txn: &DatabaseTransaction,
    client_id: i64,
    oid: OpenIdConnectCredentialOid,
) -> Result<client_openid_connect_credential::Model, ClientManagementRepositoryError> {
    let credential = CredentialEntity::find()
        .filter(CredentialColumn::Oid.eq(oid))
        .filter(CredentialColumn::ClientId.eq(client_id))
        .lock_exclusive()
        .one(txn)
        .await
        .map_err(storage)?
        .ok_or(ClientManagementRepositoryError::NotFound(
            ClientEntityKind::Credential,
        ))?;
    if credential.revoked_at.is_some() {
        return Err(ClientManagementRepositoryError::CredentialRevoked);
    }
    Ok(credential)
}

async fn revoke(
    txn: &DatabaseTransaction,
    credential: client_openid_connect_credential::Model,
) -> Result<ClientCredentialRecord, ClientManagementRepositoryError> {
    let now = Utc::now();
    let mut active: client_openid_connect_credential::ActiveModel = credential.into();
    active.revoked_at = Set(Some(now.into()));
    active.updated_at = Set(Some(now.into()));
    credential_record(active.update(txn).await.map_err(storage)?)
}

pub(super) async fn create_secret(
    db: &DatabaseConnection,
    command: CreateClientSecretTransaction,
) -> Result<ClientSecretResult, ClientManagementRepositoryError> {
    let required = if command.replaces.is_some() {
        ManagementScope::ClientCredentialsRotate
    } else {
        ManagementScope::ClientCredentialsCreate
    };
    let txn = begin(db, &command.authority, required).await?;
    let model = lock_client(&txn, command.client_oid, command.expected_version).await?;
    let revoked = match command.replaces {
        Some(oid) => {
            let credential = lock_credential(&txn, model.id, oid).await?;
            if credential.r#type != OpenIdConnectCredentialType::ClientSecret.to_string() {
                return Err(ClientManagementRepositoryError::CredentialNotSecret);
            }
            Some(revoke(&txn, credential).await?)
        }
        None => None,
    };
    let now = Utc::now();
    let serialized = serialize_data(command.secret.data.clone());
    let credential = client_openid_connect_credential::ActiveModel {
        oid: Set(command.secret.credential_oid),
        client_id: Set(model.id),
        r#type: Set(serialized.type_),
        data: Set(serialized.data),
        hint: Set(serialized.hint),
        expires_at: Set((now + Duration::days(i64::from(command.secret.lifetime_days))).into()),
        revoked_at: Set(None),
        created_at: Set(now.into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(storage)?;
    let credential = credential_record(credential)?;
    // An additional secret only widens how the client may authenticate.
    // Rotation also revokes the old secret, which withdraws what it obtained.
    finish(
        txn,
        model,
        revoked.is_some(),
        if revoked.is_some() {
            "client.secret.rotate"
        } else {
            "client.secret.create"
        },
        &command.authority,
        &command.reason,
    )
    .await?;
    Ok(ClientSecretResult {
        client: reload(db, command.client_oid).await?,
        secret: IssuedClientSecret {
            credential,
            secret: command.secret.plaintext,
        },
        revoked,
    })
}

pub(super) async fn revoke_credential(
    db: &DatabaseConnection,
    command: RevokeClientCredentialTransaction,
) -> Result<ClientCredentialRevokeResult, ClientManagementRepositoryError> {
    let txn = begin(
        db,
        &command.authority,
        ManagementScope::ClientCredentialsRevoke,
    )
    .await?;
    let model = lock_client(&txn, command.client_oid, command.expected_version).await?;
    let credential = lock_credential(&txn, model.id, command.credential_oid).await?;
    let credential = revoke(&txn, credential).await?;
    finish(
        txn,
        model,
        true,
        "client.credential.revoke",
        &command.authority,
        &command.reason,
    )
    .await?;
    Ok(ClientCredentialRevokeResult {
        client: reload(db, command.client_oid).await?,
        credential,
    })
}
