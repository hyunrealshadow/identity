use super::*;
use fixtures::*;

use crate::{
    error::{code::AppErrorCode, codes::authorize::AuthorizeErrorCode},
    openid_connect::authorize::ThirdPartyInitiatedLoginRequest,
};

#[tokio::test]
async fn third_party_initiated_login_redirects_to_registered_initiate_login_uri() {
    let service = build_test_service(
        Arc::new(InitiateLoginClientRepository {
            initiate_login_uri: Url::parse("https://rp.example.com/initiate?foo=bar").unwrap(),
        }),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryLoginRepository),
    );

    let redirect = service
        .third_party_initiated_login(ThirdPartyInitiatedLoginRequest {
            client_id: TEST_CLIENT_ID.to_string(),
            login_hint: Some("alice@example.com".to_string()),
            target_link_uri: Some(Url::parse("https://rp.example.com/orders/123").unwrap()),
        })
        .await
        .unwrap();

    assert_eq!(
        redirect.origin().ascii_serialization(),
        "https://rp.example.com"
    );
    assert_eq!(redirect.path(), "/initiate");
    let query = redirect
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<HashMap<_, _>>();
    assert_eq!(query.get("foo").unwrap(), "bar");
    assert_eq!(query.get("iss").unwrap(), "https://identity.example.com/");
    assert_eq!(query.get("client_id").unwrap(), &TEST_CLIENT_ID.to_string());
    assert_eq!(query.get("login_hint").unwrap(), "alice@example.com");
    assert_eq!(
        query.get("target_link_uri").unwrap(),
        "https://rp.example.com/orders/123"
    );
}

#[tokio::test]
async fn third_party_initiated_login_requires_registered_initiate_login_uri() {
    let service = build_test_service(
        Arc::new(FoundClientRepository),
        Arc::new(InMemoryCredentialRepository::default()),
        Arc::new(InMemoryLoginRepository),
    );

    let error = service
        .third_party_initiated_login(ThirdPartyInitiatedLoginRequest {
            client_id: TEST_CLIENT_ID.to_string(),
            login_hint: None,
            target_link_uri: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        AuthorizeErrorCode::InitiateLoginUriNotRegistered.code()
    );
}
