use crate::openid_connect::tests::fixtures::scope_catalog::TestScopeCatalog;
use crate::openid_connect::token::tests::{fixtures::*, *};
use identity_domain::auth::SessionOid;
use identity_domain::openid_connect::resource::{
    OAuthResource, OAuthResourceRepository, OAuthResourceRepositoryError,
};

struct Orders;
#[async_trait::async_trait]
impl OAuthResourceRepository for Orders {
    async fn find_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<OAuthResource>, OAuthResourceRepositoryError> {
        Ok((uri == "urn:orders").then(|| OAuthResource {
            uri: uri.into(),
            scopes: vec!["orders.read".into(), "orders.write".into()],
            enabled: true,
        }))
    }
}

#[tokio::test]
async fn custom_scopes_round_trip_through_code_tokens_and_narrowed_refresh() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let mut service =
        build_token_service_with_key(repo.clone(), key_for_algorithm("RS256"), user_oid);
    let provider = Arc::try_unwrap(provider_service())
        .ok()
        .unwrap()
        .with_scope_catalog(Arc::new(TestScopeCatalog(vec![
            "openid".into(),
            "offline_access".into(),
            "orders.read".into(),
            "orders.write".into(),
        ])))
        .with_resource_repo(Arc::new(Orders));
    service.provider_service = Arc::new(provider);
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: vec!["urn:orders".into()],
                scope: "openid offline_access orders.read orders.write".into(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                auth_time: None,
                acr: None,
                amr: vec![],
                claims: None,
                redirect_uri: "https://client.example.com/callback".into(),
                redirect_uri_was_supplied: true,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
    let response = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            resources: vec!["urn:orders".into()],
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".into()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".into()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
        })
        .await
        .unwrap();
    assert_eq!(
        response.scope,
        "openid offline_access orders.read orders.write"
    );
    let payload: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(response.access_token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["scope"], response.scope);
    let refresh = RefreshTokenGrantParams {
        resources: vec!["urn:orders".into()],
        refresh_token: response.refresh_token.unwrap(),
        scope: Some("orders.read".into()),
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".into()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    };
    let mut expansion = refresh.clone();
    expansion.scope = Some("orders".into());
    assert!(service.exchange_refresh_token(expansion).await.is_err());
    let narrowed = service.exchange_refresh_token(refresh).await.unwrap();
    assert_eq!(narrowed.scope, "orders.read");
    assert!(narrowed.id_token.is_none());
}
