use super::fixtures::*;
use super::*;
use crate::openid_connect::client_authentication::{
    ClientAuthenticator, ClientAuthenticatorDependencies,
};

/// Builds the authenticator under test with an explicit credential set.
fn authenticator(
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credentials: Vec<OpenIdConnectCredential>,
) -> ClientAuthenticator {
    ClientAuthenticator::new(ClientAuthenticatorDependencies {
        client_repo,
        credential_repo: Arc::new(cred_repo_with(credentials)),
        provider_service: provider_service(),
    })
}

fn secret_credential(secret: &str) -> OpenIdConnectCredential {
    OpenIdConnectCredential {
        oid: Uuid::new_v4(),
        client_oid: Uuid::nil(),
        r#type: OpenIdConnectCredentialType::ClientSecret,
        hint: "token".to_owned(),
        data: OpenIdConnectCredentialData::ClientSecret {
            secret: secret.to_owned(),
        },
        expires_at: Utc::now() + chrono::Duration::days(1),
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn public_key_credential(public_key: String) -> OpenIdConnectCredential {
    OpenIdConnectCredential {
        oid: Uuid::new_v4(),
        client_oid: Uuid::nil(),
        r#type: OpenIdConnectCredentialType::ClientPublicKey,
        hint: "private_key_jwt".to_owned(),
        data: OpenIdConnectCredentialData::ClientPublicKey {
            public_key,
            jwk: None,
        },
        expires_at: Utc::now() + chrono::Duration::days(1),
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

/// Signs a client assertion with the client's key, mirroring what a client
/// library does for `private_key_jwt`.
fn sign_assertion(private_key: &str, client_id: &str, with_expiry: bool) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    let now = std::time::SystemTime::now();
    payload.set_issuer(client_id);
    payload.set_subject(client_id);
    payload.set_audience(vec!["https://identity.example.com/oauth2/token"]);
    payload.set_issued_at(&now);
    if with_expiry {
        payload.set_expires_at(&(now + std::time::Duration::from_secs(300)));
    }
    payload.set_jwt_id(Uuid::new_v4().to_string());

    jwt::encode_with_signer(
        &payload,
        &header,
        &*RS256.signer_from_pem(private_key.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn authenticate_client_secret_basic_accepts_matching_secret() {
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![secret_credential("secret-123")],
    );

    let result = service
        .authenticate_client_secret_basic("00000000-0000-0000-0000-000000000000", "secret-123")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_basic_rejects_wrong_secret() {
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![secret_credential("secret-123")],
    );

    let result = service
        .authenticate_client_secret_basic("00000000-0000-0000-0000-000000000000", "wrong-secret")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_client_secret_post_accepts_matching_secret() {
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![secret_credential("secret-123")],
    );

    let result = service
        .authenticate_client_secret_post("00000000-0000-0000-0000-000000000000", "secret-123")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_jwt_accepts_hs256_assertion() {
    let service = authenticator(
        Arc::new(AuthMethodClientRepository {
            method: "client_secret_jwt",
            signing_alg: None,
        }),
        vec![secret_credential(CLIENT_SECRET_JWT_SECRET)],
    );
    let assertion = build_client_secret_assertion(
        CLIENT_SECRET_JWT_SECRET,
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_client(
            "00000000-0000-0000-0000-000000000000",
            None,
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(&assertion),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_jwt_uses_registered_signing_algorithm() {
    let service = authenticator(
        Arc::new(AuthMethodClientRepository {
            method: "client_secret_jwt",
            signing_alg: Some("HS384"),
        }),
        vec![secret_credential(CLIENT_SECRET_JWT_SECRET)],
    );
    let assertion = build_client_secret_assertion_with_algorithm(
        CLIENT_SECRET_JWT_SECRET,
        "HS384",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_client(
            "00000000-0000-0000-0000-000000000000",
            None,
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(&assertion),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_client_secret_jwt_rejects_unregistered_signing_algorithm() {
    let service = authenticator(
        Arc::new(AuthMethodClientRepository {
            method: "client_secret_jwt",
            signing_alg: Some("HS384"),
        }),
        vec![secret_credential(CLIENT_SECRET_JWT_SECRET)],
    );
    let assertion = build_client_secret_assertion_with_algorithm(
        CLIENT_SECRET_JWT_SECRET,
        "HS256",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let error = service
        .authenticate_client(
            "00000000-0000-0000-0000-000000000000",
            None,
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(&assertion),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24039);
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_signed_assertion() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![public_key_credential(public_key)],
    );
    let assertion = sign_assertion(&private_key, "00000000-0000-0000-0000-000000000000", true);

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_ok());
}

#[cfg(not(feature = "allow-none-alg"))]
#[tokio::test]
async fn authenticate_private_key_jwt_rejects_none_algorithm() {
    let service = authenticator(Arc::new(InMemoryClientRepository), vec![]);
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let mut payload = JwtPayload::new();
    payload.set_issuer("00000000-0000-0000-0000-000000000000");
    payload.set_subject("00000000-0000-0000-0000-000000000000");
    let assertion = jwt::encode_unsecured(&payload, &header).unwrap();

    let error = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24039);
}

#[tokio::test]
async fn authenticate_private_key_jwt_rejects_wrong_subject() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![public_key_credential(public_key)],
    );
    let assertion = sign_assertion(&private_key, "11111111-1111-1111-1111-111111111111", true);

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_private_key_jwt_rejects_missing_exp() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![public_key_credential(public_key)],
    );
    let assertion = sign_assertion(&private_key, &Uuid::nil().to_string(), false);

    let result = service
        .authenticate_private_key_jwt(&Uuid::nil().to_string(), &assertion)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_client_rejects_public_flow_by_default() {
    let service = authenticator(Arc::new(InMemoryClientRepository), vec![]);

    let error = service
        .authenticate_client("00000000-0000-0000-0000-000000000000", None, None, None)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24031);
}

#[tokio::test]
async fn authenticate_client_accepts_public_flow_when_enabled() {
    let service = authenticator(Arc::new(PublicFlowClientRepository), vec![]);

    let client_oid = service
        .authenticate_client("00000000-0000-0000-0000-000000000000", None, None, None)
        .await
        .unwrap();

    assert_eq!(client_oid, Uuid::nil());
}

#[tokio::test]
async fn authenticate_client_request_rejects_confidential_client_without_credentials() {
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![secret_credential("secret-123")],
    );

    let error = service
        .authenticate_client_request("00000000-0000-0000-0000-000000000000", None, None, None)
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24031);
}

#[tokio::test]
async fn authenticate_client_request_accepts_registered_public_client() {
    let service = authenticator(Arc::new(RegisteredPublicClientRepository), vec![]);

    let client = service
        .authenticate_client_request("00000000-0000-0000-0000-000000000000", None, None, None)
        .await
        .unwrap();

    assert_eq!(client.client().oid, Uuid::nil());
}

#[tokio::test]
async fn authenticate_client_request_accepts_confidential_client_with_secret() {
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![secret_credential("secret-123")],
    );

    let client = service
        .authenticate_client_request(
            "00000000-0000-0000-0000-000000000000",
            Some("secret-123"),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(client.client().oid, Uuid::nil());
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_es256_signed_assertion() {
    let key = key_data_for_algorithm("ES256");
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![public_key_credential(key.public_key.clone())],
    );
    let assertion = build_client_assertion_with_algorithm(
        &key.private_key,
        "ES256",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn authenticate_private_key_jwt_accepts_eddsa_signed_assertion() {
    let key = key_data_for_algorithm("EdDSA");
    let service = authenticator(
        Arc::new(InMemoryClientRepository),
        vec![public_key_credential(key.public_key.clone())],
    );
    let assertion = build_client_assertion_with_algorithm(
        &key.private_key,
        "EdDSA",
        "00000000-0000-0000-0000-000000000000",
        "https://identity.example.com/",
    );

    let result = service
        .authenticate_private_key_jwt("00000000-0000-0000-0000-000000000000", &assertion)
        .await;

    assert!(result.is_ok());
}
