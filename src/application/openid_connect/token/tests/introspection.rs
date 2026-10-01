use super::*;
use crate::error::{code::AppErrorCode, codes::token::TokenErrorCode};
use crate::openid_connect::token::{TokenRevocationParams, signing::SignAccessTokenInput};
use identity_domain::client_authorization::AccessTokenData;

fn request(token: String) -> TokenRevocationParams {
    TokenRevocationParams {
        token,
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    }
}

#[tokio::test]
async fn signed_access_token_returns_claims_and_tampering_is_inactive() {
    let repo = Arc::new(fixtures::mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = fixtures::build_token_service(repo.clone(), user_oid);
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AccessToken(AccessTokenData {
                scope: "openid".to_owned(),
                user_oid: user_oid.to_string(),
                session_oid: None,
                protected_session_id: None,
                authorization_code_oid: None,
                refresh_token_oid: None,
                device_authorization_oid: None,
                client_authentication_mode: None,
            }),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    let issuer = service.provider_service.issuer().unwrap();
    let (key_id, private_key_pem, alg) = service.load_signing_key().await.unwrap();
    let token_id = record.oid.to_string();
    let client_id = Uuid::nil().to_string();
    let client = service
        .client_repo
        .find_by_oid(Uuid::nil())
        .await
        .unwrap()
        .unwrap();
    let token = service
        .sign_access_token(SignAccessTokenInput {
            token_id: &token_id,
            key_id: &key_id,
            private_key_pem: &private_key_pem,
            alg,
            issuer: &issuer,
            audience: &client_id,
            client_id: &client_id,
            user_oid: &user_oid,
            client: &client,
            user: None,
            protected_session_id: None,
            scope: "openid",
            claims: None,
            auth_time: None,
            acr: None,
            amr: &[],
        })
        .await
        .unwrap();
    assert_eq!(
        service
            .introspect_token(request(format!("{token}x")))
            .await
            .unwrap(),
        serde_json::json!({"active": false})
    );
    let result = service
        .introspect_token(request(token.clone()))
        .await
        .unwrap();
    assert_eq!(result["active"], true);
    assert_eq!(result["sub"], user_oid.to_string());
    assert_eq!(result["aud"], serde_json::json!(client_id));
    let payload = service
        .verified_access_token_payload(&token)
        .await
        .unwrap()
        .unwrap();
    let signer = crate::openid_connect::jose::asymmetric_signer_from_pem(
        alg.as_str(),
        private_key_pem.as_bytes(),
    )
    .unwrap();
    let mut header = JwsHeader::new();
    header.set_token_type("at+jwt");
    header.set_key_id(&key_id);
    for (claim, value) in [
        ("exp", Some(serde_json::json!(Utc::now().timestamp() - 60))),
        ("exp", None),
        (
            "nbf",
            Some(serde_json::json!(Utc::now().timestamp() + 3600)),
        ),
        (
            "iat",
            Some(serde_json::json!(Utc::now().timestamp() + 3600)),
        ),
        ("iss", Some(serde_json::json!("https://other.example.com"))),
    ] {
        let mut invalid = payload.clone();
        invalid.set_claim(claim, value).unwrap();
        let invalid = jwt::encode_with_signer(&invalid, &header, signer.as_ref()).unwrap();
        assert_eq!(
            service.introspect_token(request(invalid)).await.unwrap(),
            serde_json::json!({"active": false})
        );
    }
    repo.revoke_if_active(record.oid, ClientAuthorizationType::AccessToken, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        service.introspect_token(request(token)).await.unwrap(),
        serde_json::json!({"active": false})
    );
}

#[tokio::test]
async fn refresh_token_checks_owner_expiry_revocation_and_unknown_tokens() {
    let repo = Arc::new(fixtures::mock_client_auth_repo());
    let service = fixtures::build_token_service(repo.clone(), Uuid::new_v4());
    for (owner, expired) in [
        (Uuid::nil(), false),
        (Uuid::new_v4(), false),
        (Uuid::nil(), true),
    ] {
        let record = repo
            .create(
                owner,
                ClientAuthorizationData::RefreshToken(RefreshTokenData {
                    scope: "openid offline_access".into(),
                    user_oid: Uuid::new_v4().to_string(),
                    session_oid: None,
                    protected_session_id: None,
                    auth_time: None,
                    acr: None,
                    amr: vec![],
                    rotated_from: None,
                    authorization_code_oid: None,
                    device_authorization_oid: None,
                    client_authentication_mode: None,
                }),
                Utc::now() + chrono::Duration::seconds(if expired { -60 } else { 3600 }),
            )
            .await
            .unwrap();
        let token = STANDARD.encode(record.oid.as_bytes());
        let result = service
            .introspect_token(request(token.clone()))
            .await
            .unwrap();
        if owner == Uuid::nil() && !expired {
            assert_eq!(result["active"], true);
            assert_eq!(result["scope"], "openid offline_access");
            repo.revoke_if_active(
                record.oid,
                ClientAuthorizationType::RefreshToken,
                Utc::now(),
            )
            .await
            .unwrap();
            assert_eq!(
                service.introspect_token(request(token)).await.unwrap(),
                serde_json::json!({"active": false})
            );
        } else {
            assert_eq!(result, serde_json::json!({"active": false}));
        }
    }
    assert_eq!(
        service
            .introspect_token(request("unknown".into()))
            .await
            .unwrap(),
        serde_json::json!({"active": false})
    );
}

#[tokio::test]
async fn introspection_requires_credentials_and_rejects_wrong_secret() {
    let service =
        fixtures::build_token_service(Arc::new(fixtures::mock_client_auth_repo()), Uuid::new_v4());
    let mut params = request("unknown".into());
    params.client_secret = None;
    assert_eq!(
        service.introspect_token(params).await.unwrap_err().code(),
        TokenErrorCode::ClientAuthRequired.code()
    );
    let mut params = request("unknown".into());
    params.client_secret = Some("wrong".into());
    assert_eq!(
        service.introspect_token(params).await.unwrap_err().code(),
        TokenErrorCode::ClientCredentialsInvalid.code()
    );
}
