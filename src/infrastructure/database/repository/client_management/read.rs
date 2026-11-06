//! Client management reads: records, keyset pages and credential metadata.

use std::collections::HashMap;

use chrono::Utc;
use identity_application::{
    client::{
        ClientCredentialRecord, ClientFilter, ClientManagementRepositoryError, ClientOrder,
        ClientPageData, ClientPageEntry, ClientPlatform, ClientProtocolSettings, ClientQuery,
        ClientRecord,
    },
    rbac::cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{client::model::ClientOid, openid_connect::OpenIdConnectCredentialType};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QueryOrder, Statement,
};

use super::support::{corrupt, storage};
use crate::database::{
    entity::{
        client,
        client::{Column as ClientColumn, Entity as ClientEntity},
        client_openid_connect::{Column as OpenIdConnectColumn, Entity as OpenIdConnectEntity},
        client_openid_connect_cors_origin::{
            Column as CorsOriginColumn, Entity as CorsOriginEntity,
        },
        client_openid_connect_credential::{
            Column as CredentialColumn, Entity as CredentialEntity, Model as CredentialModel,
        },
        client_openid_connect_platform::{Column as PlatformColumn, Entity as PlatformEntity},
    },
    repository::{
        openid_connect::mapping::{decode_client_text, to_metadata, to_platform},
        rbac_management::support::{
            Binds, CursorComparison, escape_like, keyset_condition, order_is_descending, page_flags,
        },
    },
};

pub(super) const PROTOCOL: &str = "openid_connect";

/// Build complete records for client rows, loading their protocol rows in one
/// query per table. Order follows `models`.
pub(super) async fn load_records<C: ConnectionTrait>(
    db: &C,
    models: Vec<client::Model>,
) -> Result<Vec<ClientRecord>, ClientManagementRepositoryError> {
    if models.is_empty() {
        return Ok(Vec::new());
    }
    let ids = models.iter().map(|model| model.id).collect::<Vec<_>>();
    let mut metadata = OpenIdConnectEntity::find()
        .filter(OpenIdConnectColumn::ClientId.is_in(ids.clone()))
        .all(db)
        .await
        .map_err(storage)?
        .into_iter()
        .map(|row| (row.client_id, row))
        .collect::<HashMap<_, _>>();
    let mut platforms = HashMap::<i64, Vec<ClientPlatform>>::new();
    for row in PlatformEntity::find()
        .filter(PlatformColumn::ClientId.is_in(ids.clone()))
        .order_by_asc(PlatformColumn::Platform)
        .all(db)
        .await
        .map_err(storage)?
    {
        let client_id = row.client_id;
        let platform = to_platform(row).map_err(|_| corrupt())?;
        platforms
            .entry(client_id)
            .or_default()
            .push(ClientPlatform {
                platform: platform.platform,
                redirect_uris: platform.redirect_uris,
            });
    }
    let mut origins = HashMap::<i64, Vec<String>>::new();
    for row in CorsOriginEntity::find()
        .filter(CorsOriginColumn::ClientId.is_in(ids))
        .order_by_asc(CorsOriginColumn::Origin)
        .all(db)
        .await
        .map_err(storage)?
    {
        origins.entry(row.client_id).or_default().push(row.origin);
    }

    models
        .into_iter()
        .map(|model| {
            let row = metadata.remove(&model.id).ok_or_else(corrupt)?;
            let metadata = to_metadata(row).map_err(|_| corrupt())?;
            let methods = metadata.effective_token_endpoint_auth_methods().to_vec();
            if methods.is_empty() {
                return Err(corrupt());
            }
            Ok(ClientRecord {
                oid: model.oid,
                name: model.name,
                description: model.description.unwrap_or_default(),
                names: decode_client_text(model.names).map_err(|_| corrupt())?,
                descriptions: decode_client_text(model.descriptions).map_err(|_| corrupt())?,
                built_in: model.built_in,
                enabled: model.enabled,
                settings: ClientProtocolSettings {
                    platforms: platforms.remove(&model.id).unwrap_or_default(),
                    post_logout_redirect_uris: metadata
                        .post_logout_redirect_uris
                        .iter()
                        .flatten()
                        .map(ToString::to_string)
                        .collect(),
                    grant_types: metadata.effective_grant_types().to_vec(),
                    token_endpoint_auth_methods: methods,
                    allow_public_client_flow: metadata.settings.allow_public_client_flow,
                    require_pushed_authorization_requests: metadata
                        .settings
                        .require_pushed_authorization_requests,
                    skip_consent: metadata.settings.skip_consent,
                    cors_enabled: metadata.settings.cors_enabled,
                },
                cors_origins: origins.remove(&model.id).unwrap_or_default(),
                version: model.version,
                created_at: model.created_at.with_timezone(&Utc),
                updated_at: model.updated_at.map(|value| value.with_timezone(&Utc)),
            })
        })
        .collect()
}

pub(super) async fn find_model<C: ConnectionTrait>(
    db: &C,
    oid: ClientOid,
) -> Result<Option<client::Model>, ClientManagementRepositoryError> {
    ClientEntity::find()
        .filter(ClientColumn::Oid.eq(oid))
        .filter(ClientColumn::Protocol.eq(PROTOCOL))
        .one(db)
        .await
        .map_err(storage)
}

pub(super) async fn find_record<C: ConnectionTrait>(
    db: &C,
    oid: ClientOid,
) -> Result<Option<ClientRecord>, ClientManagementRepositoryError> {
    let Some(model) = find_model(db, oid).await? else {
        return Ok(None);
    };
    Ok(load_records(db, vec![model]).await?.pop())
}

pub(super) fn credential_record(
    model: CredentialModel,
) -> Result<ClientCredentialRecord, ClientManagementRepositoryError> {
    Ok(ClientCredentialRecord {
        oid: model.oid,
        kind: model
            .r#type
            .parse::<OpenIdConnectCredentialType>()
            .map_err(|_| corrupt())?,
        hint: model.hint,
        expires_at: model.expires_at.with_timezone(&Utc),
        revoked_at: model.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: model.created_at.with_timezone(&Utc),
    })
}

pub(super) async fn list_credentials<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
) -> Result<Vec<ClientCredentialRecord>, ClientManagementRepositoryError> {
    CredentialEntity::find()
        .filter(CredentialColumn::ClientId.eq(client_id))
        .order_by_desc(CredentialColumn::CreatedAt)
        .order_by_desc(CredentialColumn::Id)
        .all(db)
        .await
        .map_err(storage)?
        .into_iter()
        .map(credential_record)
        .collect()
}

fn filter_conditions(filter: &ClientFilter, binds: &mut Binds) -> Vec<String> {
    let mut conditions = vec![format!("c.protocol = {}", binds.push(PROTOCOL))];
    if let Some(term) = &filter.query {
        let pattern = binds.push(format!("%{}%", escape_like(term)));
        let exact = binds.push(term.to_lowercase());
        conditions.push(format!("(c.name ILIKE {pattern} OR c.oid::text = {exact})"));
    }
    if let Some(enabled) = filter.enabled {
        conditions.push(format!("c.enabled = {}", binds.push(enabled)));
    }
    conditions
}

pub(super) async fn count<C: ConnectionTrait>(
    db: &C,
    filter: ClientFilter,
) -> Result<u64, ClientManagementRepositoryError> {
    let mut binds = Binds::new();
    let conditions = filter_conditions(&filter, &mut binds).join(" AND ");
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("SELECT count(*)::bigint AS total FROM client c WHERE {conditions}"),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?
        .ok_or_else(corrupt)?;
    let total = row.try_get::<i64>("", "total").map_err(storage)?;
    u64::try_from(total).map_err(|_| corrupt())
}

pub(super) async fn list<C: ConnectionTrait>(
    db: &C,
    query: ClientQuery,
) -> Result<ClientPageData, ClientManagementRepositoryError> {
    let ascending = !query.order.is_descending();
    let descending = order_is_descending(query.order.is_descending(), query.direction);
    let column = match query.order {
        ClientOrder::CreatedAtAsc | ClientOrder::CreatedAtDesc => "c.created_at",
        ClientOrder::NameAsc | ClientOrder::NameDesc => "c.name",
    };
    let mut binds = Binds::new();
    let mut conditions = filter_conditions(&query.filter, &mut binds);
    for (key, comparison) in [
        (&query.after, CursorComparison::After),
        (&query.before, CursorComparison::Before),
    ] {
        if let Some(key) = key {
            conditions.push(keyset_condition(
                column, "c.id", key, comparison, ascending, &mut binds,
            ));
        }
    }
    let direction = if descending { "DESC" } else { "ASC" };
    let limit = binds.push((query.limit + 1) as i64);
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT c.id FROM client c WHERE {} \
                 ORDER BY {column} {direction}, c.id {direction} LIMIT {limit}",
                conditions.join(" AND ")
            ),
            binds.into_values(),
        ))
        .await
        .map_err(storage)?;
    let has_more = rows.len() > query.limit;
    let mut ids = rows
        .iter()
        .take(query.limit)
        .map(|row| row.try_get::<i64>("", "id").map_err(storage))
        .collect::<Result<Vec<_>, _>>()?;
    if query.direction == RbacPageDirection::Backward {
        ids.reverse();
    }
    let mut models = ClientEntity::find()
        .filter(ClientColumn::Id.is_in(ids.clone()))
        .all(db)
        .await
        .map_err(storage)?
        .into_iter()
        .map(|model| (model.id, model))
        .collect::<HashMap<_, _>>();
    let ordered = ids
        .iter()
        .map(|id| models.remove(id).ok_or_else(corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    let keys = ordered
        .iter()
        .map(|model| {
            let tie = RbacTie::Id(model.id);
            match query.order {
                ClientOrder::CreatedAtAsc | ClientOrder::CreatedAtDesc => RbacSortKey::CreatedAt {
                    created_at: model.created_at.with_timezone(&Utc),
                    tie,
                },
                ClientOrder::NameAsc | ClientOrder::NameDesc => RbacSortKey::Text {
                    value: model.name.clone(),
                    tie,
                },
            }
        })
        .collect::<Vec<_>>();
    let records = load_records(db, ordered).await?;
    let (has_previous_page, has_next_page) = page_flags(
        query.direction,
        has_more,
        query.after.is_some(),
        query.before.is_some(),
    );
    Ok(ClientPageData {
        items: records
            .into_iter()
            .zip(keys)
            .map(|(record, sort_key)| ClientPageEntry { sort_key, record })
            .collect(),
        has_previous_page,
        has_next_page,
    })
}
