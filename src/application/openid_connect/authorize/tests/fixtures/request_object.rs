use super::*;
use crate::openid_connect::authorize::tests::fixtures::repositories::{
    ClientAuthorizationState, mock_client_auth_repo_with_state,
};
use crate::openid_connect::tests::fixtures::mocks::{
    MockKeyJwkRepository, MockOpenIdConnectCredentialRepository,
};

pub(in crate::openid_connect) fn signing_keypair() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    (
        rsa.private_key_to_pem().unwrap(),
        rsa.public_key_to_pem().unwrap(),
    )
}

pub(in crate::openid_connect) fn authorize_service_with_public_key(
    public_key: Vec<u8>,
) -> AuthorizeService {
    let creds = vec![OpenIdConnectCredential {
        oid: Uuid::new_v4(),
        client_oid: TEST_CLIENT_ID,
        r#type: OpenIdConnectCredentialType::ClientPublicKey,
        hint: "request_object".to_string(),
        data: OpenIdConnectCredentialData::ClientPublicKey {
            public_key: String::from_utf8(public_key).unwrap(),
            jwk: None,
        },
        expires_at: chrono::Utc::now(),
        revoked_at: None,
        created_at: chrono::Utc::now(),
        updated_at: None,
    }];
    let mut credential_repo = MockOpenIdConnectCredentialRepository::new();
    credential_repo
        .expect_find_by_client_oid_and_type()
        .returning(move |_, _| Ok(creds.clone()));

    AuthorizeService::new(AuthorizeServiceDependencies {
        client_repo: Arc::new(FoundClientRepository),
        credential_repo: Arc::new(credential_repo),
        client_authorization_repo: Arc::new(mock_client_auth_repo_with_state(Arc::new(
            ClientAuthorizationState::default(),
        ))),
        login_repo: Arc::new(mock_login_repo()),
        user_repo: Arc::new(stub_user_repo()),
        key_repo: Arc::new(stub_key_repo()),
        key_jwk_repo: Arc::new(MockKeyJwkRepository::new()),
        provider_service: provider_service(),
        signing_algorithm_detector: test_signing_algorithm_detector(),
        data_protector: test_data_protector(),
        http_client: crate::openid_connect::remote::test_http_client(),
    })
}

pub(in crate::openid_connect) fn authorize_service_with_request_uri(
    request_uri: &str,
) -> AuthorizeService {
    AuthorizeService::new(AuthorizeServiceDependencies {
        client_repo: Arc::new(RequestUriClientRepository {
            request_uris: vec![Url::parse(request_uri).unwrap()],
        }),
        credential_repo: Arc::new(empty_cred_repo()),
        client_authorization_repo: Arc::new(mock_client_auth_repo_with_state(Arc::new(
            ClientAuthorizationState::default(),
        ))),
        login_repo: Arc::new(mock_login_repo()),
        user_repo: Arc::new(stub_user_repo()),
        key_repo: Arc::new(stub_key_repo()),
        key_jwk_repo: Arc::new(MockKeyJwkRepository::new()),
        provider_service: provider_service(),
        signing_algorithm_detector: test_signing_algorithm_detector(),
        data_protector: test_data_protector(),
        http_client: crate::openid_connect::remote::test_http_client(),
    })
}

pub(in crate::openid_connect) async fn spawn_chunked_response_server(
    chunks: Vec<Vec<u8>>,
    keep_open_for: Duration,
) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
                )
                .await
                .unwrap();

        for chunk in chunks {
            stream
                .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(&chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
        }

        tokio::time::sleep(keep_open_for).await;
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

pub(in crate::openid_connect) async fn spawn_redirect_response_server(_location: &str) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let location = format!("http://{address}/final.jwt");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

pub(in crate::openid_connect) fn signed_request_object(
    private_key: &[u8],
    fields: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    for (name, value) in fields {
        payload.set_claim(name, Some(value)).unwrap();
    }

    let signer = RS256.signer_from_pem(private_key).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}
