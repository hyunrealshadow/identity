use identity_domain::auth::SessionOid;
use identity_domain::client::model::ClientOid;
use identity_domain::openid_connect::{
    OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
};

mockall::mock! {
    pub OpenIdConnectClientRepository {}

    #[async_trait::async_trait]
    impl OpenIdConnectClientRepository for OpenIdConnectClientRepository {
        async fn find_by_oid(&self, oid: ClientOid)
            -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;
        async fn find_frontchannel_logout_clients_by_session_oid(&self, session_oid: SessionOid)
            -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;
        async fn find_backchannel_logout_clients_by_session_oid(&self, session_oid: SessionOid)
            -> Result<Vec<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;
    }
}
