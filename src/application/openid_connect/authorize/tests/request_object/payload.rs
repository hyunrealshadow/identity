use crate::openid_connect::authorize::tests::fixtures::repositories::{
    ClientAuthorizationState, mock_client_auth_repo_with_state,
};
use crate::openid_connect::authorize::tests::fixtures::*;
use crate::openid_connect::authorize::tests::*;
use crate::openid_connect::tests::fixtures::client::{
    test_client, test_metadata, test_platforms, test_scopes,
};
use crate::openid_connect::tests::fixtures::mocks::{
    MockKeyJwkRepository, MockOpenIdConnectCredentialRepository,
};

#[tokio::test]
async fn parse_request_object_payload_preserves_registered_claims() {
    let (private_key, public_key) = signing_keypair();
    let service = authorize_service_with_public_key(public_key);
    let client = FoundClientRepository
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    let jwt = signed_request_object(
        &private_key,
        [
            ("response_type", json!("code")),
            ("client_id", json!(TEST_CLIENT_ID)),
            ("redirect_uri", json!("https://client.example.com/callback")),
            ("scope", json!("openid profile")),
            ("iss", json!(TEST_CLIENT_ID)),
            ("aud", json!("https://identity.example.com/")),
            ("exp", json!(now + 300)),
            ("nbf", json!(now - 10)),
        ],
    );

    let parsed = service
        .parse_request_object_payload(&client, &jwt)
        .await
        .unwrap();

    assert_eq!(parsed["iss"], json!(TEST_CLIENT_ID));
    assert_eq!(parsed["aud"], json!("https://identity.example.com/"));
    assert_eq!(parsed["exp"], json!(now + 300));
    assert_eq!(parsed["nbf"], json!(now - 10));
}

#[tokio::test]
async fn parse_unsecured_request_object_is_accepted() {
    let service = AuthorizeService::new(AuthorizeServiceDependencies {
        client_repo: Arc::new(FoundClientRepository),
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
    });
    let client = FoundClientRepository
        .find_by_oid(Uuid::nil())
        .await
        .unwrap()
        .unwrap();
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    payload
        .set_claim("scope", Some(serde_json::json!("openid email")))
        .unwrap();
    payload
        .set_claim("state", Some(serde_json::json!("request-state")))
        .unwrap();

    let jwt = jwt::encode_unsecured(&payload, &header).unwrap();
    let result = service.parse_request_object_payload(&client, &jwt).await;

    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed["scope"], "openid email");
    assert_eq!(parsed["state"], "request-state");
}

#[tokio::test]
async fn parse_unsecured_request_object_rejects_non_empty_signature() {
    let service = authorize_service_with_public_key(signing_keypair().1);
    let client = FoundClientRepository
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    payload
        .set_claim("scope", Some(serde_json::json!("openid")))
        .unwrap();
    let mut token = jwt::encode_unsecured(&payload, &header).unwrap();
    token.push_str("forged-signature");

    let error = service
        .parse_request_object_payload(&client, &token)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23041);
}

#[tokio::test]
async fn parse_rsa_encrypted_signed_request_object() {
    let (client_private_key, client_public_key) = signing_keypair();
    let (encryption_private_key, encryption_public_key) = signing_keypair();
    let kid = Uuid::new_v4().to_string();
    let service = authorize_service_with_request_object_encryption_key(
        client_public_key,
        encryption_private_key,
        encryption_public_key.clone(),
        &kid,
        "RSA-OAEP",
    );
    let client = FoundClientRepository
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    let inner = signed_request_object(
        &client_private_key,
        [
            ("client_id", json!(TEST_CLIENT_ID)),
            ("scope", json!("openid profile")),
            ("state", json!("encrypted-state")),
        ],
    );
    let mut header = JweHeader::new();
    header.set_algorithm("RSA-OAEP");
    header.set_content_encryption("A128GCM");
    header.set_key_id(&kid);
    header.set_content_type("JWT");
    let encrypter = RSA_OAEP.encrypter_from_pem(&encryption_public_key).unwrap();
    let encrypted = serialize_compact(inner.as_bytes(), &header, &encrypter).unwrap();

    let parsed = service
        .parse_request_object_payload(&client, &encrypted)
        .await
        .unwrap();

    assert_eq!(parsed["client_id"], TEST_CLIENT_ID.to_string());
    assert_eq!(parsed["scope"], "openid profile");
    assert_eq!(parsed["state"], "encrypted-state");
}

#[tokio::test]
async fn parse_ecdh_encrypted_signed_request_object() {
    let (client_private_key, client_public_key) = signing_keypair();
    let encryption_key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let encryption_private_key = encryption_key_pair.to_pem_private_key();
    let encryption_public_key = encryption_key_pair.to_pem_public_key();
    let kid = Uuid::new_v4().to_string();
    let service = authorize_service_with_request_object_encryption_key(
        client_public_key,
        encryption_private_key,
        encryption_public_key.clone(),
        &kid,
        "ECDH-ES",
    );
    let client = FoundClientRepository
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    let inner = signed_request_object(
        &client_private_key,
        [
            ("client_id", json!(TEST_CLIENT_ID)),
            ("scope", json!("openid")),
            ("state", json!("ecdh-state")),
        ],
    );
    let mut header = JweHeader::new();
    header.set_algorithm("ECDH-ES");
    header.set_content_encryption("A256GCM");
    header.set_key_id(&kid);
    header.set_content_type("JWT");
    let encrypter = ECDH_ES.encrypter_from_pem(&encryption_public_key).unwrap();
    let encrypted = serialize_compact(inner.as_bytes(), &header, &encrypter).unwrap();

    let parsed = service
        .parse_request_object_payload(&client, &encrypted)
        .await
        .unwrap();

    assert_eq!(parsed["scope"], "openid");
    assert_eq!(parsed["state"], "ecdh-state");
}

#[tokio::test]
async fn parse_encrypted_request_object_rejects_malformed_protected_header() {
    let service = authorize_service_with_public_key(signing_keypair().1);
    let client = FoundClientRepository
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();

    let result = service
        .parse_request_object_payload(&client, "header.encrypted_key.iv.ciphertext.tag")
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), 23023);
}

#[tokio::test]
async fn parse_encrypted_request_object_enforces_registered_alg_and_enc() {
    let service = authorize_service_with_public_key(signing_keypair().1);
    let mut metadata = test_metadata(None, None);
    metadata.request_object_encryption_alg = Some("RSA-OAEP-256".to_owned());
    metadata.request_object_encryption_enc = Some("A256GCM".to_owned());
    let client = OpenIdConnectClient::new(
        test_client(TEST_CLIENT_ID),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap();
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RSA-OAEP",
            "enc": "A128GCM"
        }))
        .unwrap(),
    );

    let error = service
        .parse_request_object_payload(&client, &format!("{protected}.key.iv.ciphertext.tag"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23061);
}

#[tokio::test]
async fn parse_encrypted_request_object_rejects_unknown_kid() {
    let (client_private_key, client_public_key) = signing_keypair();
    let (encryption_private_key, encryption_public_key) = signing_keypair();
    let service = authorize_service_with_request_object_encryption_key(
        client_public_key,
        encryption_private_key,
        encryption_public_key.clone(),
        &Uuid::new_v4().to_string(),
        "RSA-OAEP",
    );
    let client = FoundClientRepository
        .find_by_oid(TEST_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    let inner = signed_request_object(
        &client_private_key,
        [
            ("client_id", json!(TEST_CLIENT_ID)),
            ("scope", json!("openid")),
        ],
    );
    let mut header = JweHeader::new();
    header.set_algorithm("RSA-OAEP");
    header.set_content_encryption("A128GCM");
    header.set_key_id(Uuid::new_v4().to_string());
    let encrypter = RSA_OAEP.encrypter_from_pem(&encryption_public_key).unwrap();
    let encrypted = serialize_compact(inner.as_bytes(), &header, &encrypter).unwrap();

    let error = service
        .parse_request_object_payload(&client, &encrypted)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 23061);
}

#[tokio::test]
async fn parse_rs256_request_object_extracts_payload() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = rsa.private_key_to_pem().unwrap();
    let public_key = rsa.public_key_to_pem().unwrap();

    let creds = vec![OpenIdConnectCredential {
        oid: Uuid::new_v4(),
        client_oid: Uuid::nil(),
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

    let service = AuthorizeService::new(AuthorizeServiceDependencies {
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
    });

    let client = FoundClientRepository
        .find_by_oid(Uuid::nil())
        .await
        .unwrap()
        .unwrap();
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    payload
        .set_claim("scope", Some(serde_json::json!("openid email")))
        .unwrap();
    let signer = RS256.signer_from_pem(&private_key).unwrap();
    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let parsed = service
        .parse_request_object_payload(&client, &jwt)
        .await
        .unwrap();

    assert_eq!(parsed["scope"], "openid email");
}

#[tokio::test]
async fn parse_request_object_uses_registered_signing_algorithm() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = rsa.private_key_to_pem().unwrap();
    let public_key = rsa.public_key_to_pem().unwrap();

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
    let service = AuthorizeService::new(AuthorizeServiceDependencies {
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
    });
    let mut metadata = test_metadata(None, None);
    metadata.request_object_signing_alg = Some("RS384".to_owned());
    let client = OpenIdConnectClient::new(
        test_client(TEST_CLIENT_ID),
        metadata,
        test_platforms(),
        test_scopes(),
    )
    .unwrap();

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    payload
        .set_claim("scope", Some(serde_json::json!("openid email")))
        .unwrap();
    let signer = RS256.signer_from_pem(&private_key).unwrap();
    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let result = service.parse_request_object_payload(&client, &jwt).await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), 23028);
}
