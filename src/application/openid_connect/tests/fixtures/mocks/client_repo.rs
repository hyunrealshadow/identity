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

/// Creates a MockOpenIdConnectClientRepository that always returns a client
/// built from the helper functions.
pub fn client_repo_always_found() -> MockOpenIdConnectClientRepository {
    let mut mock = MockOpenIdConnectClientRepository::new();
    mock.expect_find_by_oid().returning(move |oid| {
        use crate::openid_connect::tests::fixtures::client::{
            test_client, test_metadata, test_platforms, test_scopes,
        };
        Ok(Some(
            OpenIdConnectClient::new(
                test_client(oid),
                test_metadata(None, Some("client_secret_basic")),
                test_platforms(),
                test_scopes(),
            )
            .unwrap(),
        ))
    });
    mock.expect_find_frontchannel_logout_clients_by_session_oid()
        .returning(|_session_oid| Ok(vec![]));
    mock.expect_find_backchannel_logout_clients_by_session_oid()
        .returning(|_session_oid| Ok(vec![]));
    mock
}

/// Creates a MockOpenIdConnectClientRepository that returns a client with
/// public client flow enabled.
pub fn client_repo_public_flow() -> MockOpenIdConnectClientRepository {
    let mut mock = MockOpenIdConnectClientRepository::new();
    mock.expect_find_by_oid().returning(move |oid| {
        use crate::openid_connect::tests::fixtures::client::{
            test_client, test_metadata, test_platforms, test_scopes,
        };
        let mut metadata = test_metadata(None, Some("client_secret_basic"));
        metadata.settings.allow_public_client_flow = true;
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    });
    mock.expect_find_frontchannel_logout_clients_by_session_oid()
        .returning(|_session_oid| Ok(vec![]));
    mock.expect_find_backchannel_logout_clients_by_session_oid()
        .returning(|_session_oid| Ok(vec![]));
    mock
}

/// Creates a MockOpenIdConnectClientRepository that returns a client with
/// the specified auth method and optional signing alg.
pub fn client_repo_with_auth_method(
    method: &'static str,
    signing_alg: Option<&'static str>,
) -> MockOpenIdConnectClientRepository {
    let mut mock = MockOpenIdConnectClientRepository::new();
    mock.expect_find_by_oid().returning(move |oid| {
        use crate::openid_connect::tests::fixtures::client::{
            test_client, test_metadata, test_platforms, test_scopes,
        };
        let mut metadata = test_metadata(None, Some(method));
        metadata.token_endpoint_auth_signing_alg = signing_alg.map(str::to_owned);
        Ok(Some(
            OpenIdConnectClient::new(test_client(oid), metadata, test_platforms(), test_scopes())
                .unwrap(),
        ))
    });
    mock.expect_find_frontchannel_logout_clients_by_session_oid()
        .returning(|_session_oid| Ok(vec![]));
    mock.expect_find_backchannel_logout_clients_by_session_oid()
        .returning(|_session_oid| Ok(vec![]));
    mock
}
