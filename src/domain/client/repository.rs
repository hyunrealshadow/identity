use super::model::{Client, ClientOid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRepositoryError {
    Unavailable,
}

#[async_trait::async_trait]
pub trait ClientRepository: Send + Sync {
    async fn find_by_oid(&self, oid: ClientOid) -> Result<Option<Client>, ClientRepositoryError>;
}
