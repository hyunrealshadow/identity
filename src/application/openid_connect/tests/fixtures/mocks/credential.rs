use identity_domain::client::model::ClientOid;
use identity_domain::openid_connect::{
    OpenIdConnectCredential, OpenIdConnectCredentialOid, OpenIdConnectCredentialRepository,
    OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
};

mockall::mock! {
    pub OpenIdConnectCredentialRepository {}

    #[async_trait::async_trait]
    impl OpenIdConnectCredentialRepository for OpenIdConnectCredentialRepository {
        async fn find_by_oid(&self, oid: OpenIdConnectCredentialOid)
            -> Result<Option<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>;
        async fn find_by_client_oid_and_type(&self, client_oid: ClientOid, type_: OpenIdConnectCredentialType)
            -> Result<Vec<OpenIdConnectCredential>, OpenIdConnectCredentialRepositoryError>;
    }
}
