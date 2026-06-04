use identity_domain::client::model::ClientOid;
use identity_domain::openid_connect::{
    OpenIdConnectClient, OpenIdConnectClientRegistration,
    OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepositoryError,
};

mockall::mock! {
    pub OpenIdConnectClientRegistrationRepository {}

    #[async_trait::async_trait]
    impl OpenIdConnectClientRegistrationRepository for OpenIdConnectClientRegistrationRepository {
        async fn create(&self, registration: OpenIdConnectClientRegistration)
            -> Result<ClientOid, OpenIdConnectClientRepositoryError>;
        async fn find_by_registration_access_token(&self, client_oid: ClientOid, token: &str)
            -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;
        async fn delete_by_oid(&self, client_oid: ClientOid)
            -> Result<(), OpenIdConnectClientRepositoryError>;
    }
}
