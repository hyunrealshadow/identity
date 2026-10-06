use identity_domain::{
    client::model::ClientOid,
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectClientRegistration,
        OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepositoryError,
    },
};
use mockall::mock;

mock! {
    pub OpenIdConnectClientRegistrationRepository {}

    #[async_trait::async_trait]
    impl OpenIdConnectClientRegistrationRepository for OpenIdConnectClientRegistrationRepository {
        async fn update(&self, registration: OpenIdConnectClientRegistration, token: &str, current_secret: Option<String>)
            -> Result<(), OpenIdConnectClientRepositoryError>;
        async fn create(&self, registration: OpenIdConnectClientRegistration)
            -> Result<ClientOid, OpenIdConnectClientRepositoryError>;
        async fn find_by_registration_access_token(&self, client_oid: ClientOid, token: &str)
            -> Result<Option<OpenIdConnectClient>, OpenIdConnectClientRepositoryError>;
        async fn delete_by_oid(&self, client_oid: ClientOid)
            -> Result<(), OpenIdConnectClientRepositoryError>;
    }
}
