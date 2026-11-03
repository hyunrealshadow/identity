use crate::openid_connect::authorize::tests::fixtures::*;
use crate::openid_connect::authorize::tests::*;

#[tokio::test]
async fn validate_request_uri_rejects_unregistered_public_target() {
    let service = authorize_service_with_request_uri("https://client.example.com/registered.jwt");
    let params = AuthorizationRequestParams {
        resources: Vec::new(),
        request_uri: Some("https://client.example.com/unregistered.jwt".to_string()),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23018); // RequestUriNotRegistered
}

#[tokio::test]
async fn validate_request_uri_rejects_loopback_target() {
    let service = authorize_service_with_request_uri("https://127.0.0.1/request.jwt");
    let params = AuthorizationRequestParams {
        resources: Vec::new(),
        request_uri: Some("https://127.0.0.1/request.jwt".to_string()),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "loopback must be blocked"); // RequestUriUnsafeHost
}
