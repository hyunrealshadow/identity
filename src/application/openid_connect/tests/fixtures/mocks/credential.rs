use identity_domain::{
    client::model::ClientOid,
    openid_connect::{
        OpenIdConnectCredential, OpenIdConnectCredentialRepository,
        OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
    },
};
use mockall::mock;

mock! {
    pub OpenIdConnectCredentialRepository {}

    #[async_trait::async_trait]
    impl OpenIdConnectCredentialRepository for OpenIdConnectCredentialRepository {
        async fn find_active_by_client_oid_and_type(&self, client_oid: ClientOid, type_: OpenIdConnectCredentialType)
            -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>;
    }
}
