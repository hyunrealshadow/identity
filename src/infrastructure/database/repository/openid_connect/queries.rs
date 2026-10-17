use super::mapping::{to_client, to_metadata, to_platform};
use crate::database::entity::{
    client, client::Entity as ClientEntity, client_openid_connect,
    client_openid_connect::Entity as OpenIdConnectClientEntity, client_openid_connect_platform,
    client_openid_connect_platform::Entity as ClientOpenIdConnectPlatformEntity, client_scope,
    client_scope::Entity as ClientScopeEntity, login, login::Entity as LoginEntity, scope,
    scope::Entity as ScopeEntity, session, session::Entity as SessionEntity,
};
use async_trait::async_trait;
use identity_domain::{
    auth::SessionOid,
    client::model::ClientOid,
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
    },
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use std::collections::BTreeMap;
use uuid::Uuid;

pub struct OpenIdConnectClientRepositoryImpl {
    pub(super) db: DatabaseConnection,
}

impl OpenIdConnectClientRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl OpenIdConnectClientRepository for OpenIdConnectClientRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_oid"))]
    async fn find_by_oid(
        &self,
        oid: ClientOid,
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
        let mut platforms_by_client = BTreeMap::<i64, Vec<_>>::new();
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
        let mut scopes_by_client = BTreeMap::<i64, Vec<String>>::new();
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
