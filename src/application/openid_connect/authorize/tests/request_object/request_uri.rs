use super::super::fixtures::*;
use super::super::*;

#[tokio::test]
async fn validate_request_uri_rejects_fragment() {
    let service =
        authorize_service_with_request_uri("https://client.example.com/request.jwt#fragment");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://client.example.com/request.jwt#fragment".to_string()),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23016); // RequestUriHasFragment
}

#[tokio::test]
async fn validate_request_uri_rejects_loopback_target() {
    let service = authorize_service_with_request_uri("https://127.0.0.1/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://127.0.0.1/request.jwt".to_string()),
        ..params("openid profile")
    };

    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "loopback must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_rfc1918_class_a() {
    let service = authorize_service_with_request_uri("https://10.0.0.1/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://10.0.0.1/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "10.x.x.x must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_rfc1918_class_b() {
    let service = authorize_service_with_request_uri("https://172.16.0.1/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://172.16.0.1/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "172.16.x must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_rfc1918_class_b_upper_bound() {
    let service = authorize_service_with_request_uri("https://172.31.255.255/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://172.31.255.255/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "172.31.x must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_rfc1918_class_c() {
    let service = authorize_service_with_request_uri("https://192.168.1.100/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://192.168.1.100/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "192.168.x must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_link_local_ipv4() {
    let service = authorize_service_with_request_uri("https://169.254.1.1/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://169.254.1.1/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "169.254.x link-local must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_ipv6_loopback() {
    let service = authorize_service_with_request_uri("https://[::1]/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://[::1]/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "::1 loopback must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_ipv6_ula() {
    let service = authorize_service_with_request_uri("https://[fc00::1]/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://[fc00::1]/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "fc00::/7 ULA must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn validate_request_uri_rejects_ipv6_link_local() {
    let service = authorize_service_with_request_uri("https://[fe80::1]/request.jwt");
    let params = AuthorizationRequestParams {
        request_uri: Some("https://[fe80::1]/request.jwt".to_string()),
        ..params("openid profile")
    };
    let error = service.validate_request(params).await.unwrap_err();
    assert_eq!(error.code(), 23017, "fe80::/10 link-local must be blocked"); // RequestUriUnsafeHost
}

#[tokio::test]
async fn fetch_request_object_rejects_oversized_chunked_response_before_completion() {
    let service = authorize_service_with_request_uri("https://client.example.com/request.jwt");
    let request_uri = spawn_chunked_response_server(
        vec![vec![b'a'; 1024 * 1024], vec![b'b'; 1]],
        Duration::from_secs(6),
    )
    .await;

    let result = timeout(
        Duration::from_secs(2),
        service.fetch_request_object(&request_uri),
    )
    .await;

    let error = result
        .expect("oversized response should be rejected before server finishes")
        .unwrap_err();
    assert_eq!(error.code(), 23021); // RequestUriTooLarge
}

#[tokio::test]
async fn fetch_request_object_rejects_redirect_response() {
    let service = authorize_service_with_request_uri("https://client.example.com/request.jwt");
    let request_uri = spawn_redirect_response_server("http://127.0.0.1/final.jwt").await;

    let error = service
        .fetch_request_object(&request_uri)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23020); // RequestUriNot200
}
