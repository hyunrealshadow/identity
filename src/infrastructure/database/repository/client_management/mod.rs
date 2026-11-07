//! SeaORM implementation of OAuth client management persistence.

mod read;
mod support;
mod write;

use async_trait::async_trait;
use identity_application::client::{
    AddClientCredentialTransaction, ClientCredentialRecord, ClientCredentialResult,
    ClientCredentialRevokeResult, ClientFilter, ClientManagementRepository,
    ClientManagementRepositoryError, ClientPageData, ClientQuery, ClientRecord, ClientSecretResult,
    ClientStateTransaction, CreateClientSecretTransaction, CreateClientTransaction,
    RevokeClientCredentialTransaction, UpdateClientTransaction,
};
use identity_domain::client::model::ClientOid;
use sea_orm::DatabaseConnection;

pub struct ClientManagementRepositoryImpl {
    db: DatabaseConnection,
}

impl ClientManagementRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ClientManagementRepository for ClientManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "client.count"))]
    async fn count_clients(
        &self,
        filter: ClientFilter,
    ) -> Result<u64, ClientManagementRepositoryError> {
        read::count(&self.db, filter).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "client.list"))]
    async fn list_clients(
        &self,
        query: ClientQuery,
    ) -> Result<ClientPageData, ClientManagementRepositoryError> {
        read::list(&self.db, query).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "client.find"))]
    async fn find_client(
        &self,
        oid: ClientOid,
    ) -> Result<Option<ClientRecord>, ClientManagementRepositoryError> {
        read::find_record(&self.db, oid).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "client.credentials"))]
    async fn list_client_credentials(
        &self,
        oid: ClientOid,
    ) -> Result<Vec<ClientCredentialRecord>, ClientManagementRepositoryError> {
        let Some(model) = read::find_model(&self.db, oid).await? else {
            return Ok(Vec::new());
        };
        read::list_credentials(&self.db, model.id).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.create"))]
    async fn create_client(
        &self,
        command: CreateClientTransaction,
    ) -> Result<ClientRecord, ClientManagementRepositoryError> {
        write::create(&self.db, command).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.update"))]
    async fn update_client(
        &self,
        command: UpdateClientTransaction,
    ) -> Result<ClientRecord, ClientManagementRepositoryError> {
        write::update(&self.db, command).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.state"))]
    async fn set_client_enabled(
        &self,
        command: ClientStateTransaction,
        enabled: bool,
    ) -> Result<ClientRecord, ClientManagementRepositoryError> {
        write::set_enabled(&self.db, command, enabled).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.delete"))]
    async fn delete_client(
        &self,
        command: ClientStateTransaction,
    ) -> Result<ClientOid, ClientManagementRepositoryError> {
        write::delete(&self.db, command).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.secret.create"))]
    async fn create_client_secret(
        &self,
        command: CreateClientSecretTransaction,
    ) -> Result<ClientSecretResult, ClientManagementRepositoryError> {
        write::create_secret(&self.db, command).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.credential.add"))]
    async fn add_client_credential(
        &self,
        command: AddClientCredentialTransaction,
    ) -> Result<ClientCredentialResult, ClientManagementRepositoryError> {
        write::add_credential(&self.db, command).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "client.credential.revoke"))]
    async fn revoke_client_credential(
        &self,
        command: RevokeClientCredentialTransaction,
    ) -> Result<ClientCredentialRevokeResult, ClientManagementRepositoryError> {
        write::revoke_credential(&self.db, command).await
    }
}
