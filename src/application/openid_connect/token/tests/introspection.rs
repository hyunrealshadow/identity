use chrono::Duration;
use identity_domain::{
    auth::SessionOid,
    client_authorization::{AccessTokenData, AccessTokenPrincipal},
};
use serde_json::json;

use crate::{
    error::{code::AppErrorCode, codes::token::TokenErrorCode},
    openid_connect::{
        jose::asymmetric_signer_from_pem,
        token::{TokenRevocationParams, signing::SignAccessTokenInput},
    },
};

use super::*;

fn request(token: String) -> TokenRevocationParams {
    TokenRevocationParams {
        token,
        client_id: Some(identity_domain::openid_connect::identifier::client_id(
            Uuid::nil(),
        )),
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
                resources: Vec::new(),
                user_oid: Some(user_oid.to_string()),
                principal: AccessTokenPrincipal::User,
                session_oid: Some(SessionOid::from(Uuid::new_v4())),
                protected_session_id: None,
                authorization_code_oid: None,
                refresh_token_oid: None,
                device_authorization_oid: None,
                client_authentication_mode: None,
                claims: None,
                management: None,
            }),
            Utc::now() + Duration::hours(1),
        )
        .await
        .unwrap();
    let issuer = service.provider_service.issuer().unwrap();
    let (key_id, private_key_pem, alg) = service.load_signing_key().await.unwrap();
    let token_id = identity_domain::openid_connect::identifier::access_token_id(record.oid);
    let client_id = identity_domain::openid_connect::identifier::client_id(Uuid::nil());
    let client = service
        .client_repo
        .find_by_oid(Uuid::nil())
        .await
        .unwrap()
        .unwrap();
    let token = service
        .sign_access_token(SignAccessTokenInput {
            resources: &[],
            token_id: &token_id,
            key_id: &key_id,
            private_key_pem: &private_key_pem,
            alg,
            issuer: &issuer,
            audience: &client_id,
            client_id: &client_id,
            subject: &identity_domain::openid_connect::identifier::user_subject(user_oid),
            principal: AccessTokenPrincipal::User,
            client: &client,
            user: None,
            protected_session_id: None,
            scope: "openid",
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
        json!({"active": false})
    );
    let result = service
        .introspect_token(request(token.clone()))
        .await
        .unwrap();
    assert_eq!(result["active"], true);
    assert_eq!(
        result["sub"],
        identity_domain::openid_connect::identifier::user_subject(user_oid)
    );
    assert_eq!(result["aud"], json!(client_id));
    let payload = service
        .verified_access_token_payload(&token)
        .await
        .unwrap()
        .unwrap();
    let signer = asymmetric_signer_from_pem(alg.as_str(), private_key_pem.as_bytes()).unwrap();
    let mut header = JwsHeader::new();
    header.set_token_type("at+jwt");
    header.set_key_id(&key_id);
    for (claim, value) in [
        ("exp", Some(json!(Utc::now().timestamp() - 60))),
        ("exp", None),
        ("nbf", Some(json!(Utc::now().timestamp() + 3600))),
        ("iat", Some(json!(Utc::now().timestamp() + 3600))),
        ("iss", Some(json!("https://other.example.com"))),
    ] {
        let mut invalid = payload.clone();
        invalid.set_claim(claim, value).unwrap();
        let invalid = jwt::encode_with_signer(&invalid, &header, signer.as_ref()).unwrap();
        assert_eq!(
            service.introspect_token(request(invalid)).await.unwrap(),
            json!({"active": false})
        );
    }
    repo.revoke_if_active(record.oid, ClientAuthorizationType::AccessToken, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        service.introspect_token(request(token)).await.unwrap(),
        json!({"active": false})
    );
}

#[tokio::test]
async fn refresh_token_checks_owner_expiry_revocation_and_unknown_tokens() {
    let repo = Arc::new(fixtures::mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = fixtures::build_token_service(repo.clone(), user_oid);
    for (owner, expired) in [
        (Uuid::nil(), false),
        (Uuid::new_v4(), false),
        (Uuid::nil(), true),
    ] {
        let record = repo
            .create(
                owner,
                ClientAuthorizationData::RefreshToken(RefreshTokenData {
                    resources: Vec::new(),
                    scope: "openid offline_access".into(),
                    user_oid: user_oid.to_string(),
                    session_oid: Some(SessionOid::from(Uuid::new_v4())),
                    protected_session_id: None,
                    auth_time: None,
                    acr: None,
                    amr: vec![],
                    rotated_from: None,
                    authorization_code_oid: None,
                    device_authorization_oid: None,
                    client_authentication_mode: None,
                    management: None,
                }),
                Utc::now() + Duration::seconds(if expired { -60 } else { 3600 }),
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
                json!({"active": false})
            );
        } else {
            assert_eq!(result, json!({"active": false}));
        }
    }
    assert_eq!(
        service
            .introspect_token(request("unknown".into()))
            .await
            .unwrap(),
        json!({"active": false})
    );
}

#[tokio::test]
async fn machine_access_token_introspects_with_the_client_subject() {
    let repo = Arc::new(fixtures::mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = fixtures::build_token_service(repo.clone(), user_oid);
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AccessToken(AccessTokenData {
                scope: "account.read".to_owned(),
                resources: Vec::new(),
                user_oid: None,
                principal: AccessTokenPrincipal::Client,
                session_oid: None,
                protected_session_id: None,
                authorization_code_oid: None,
                refresh_token_oid: None,
                device_authorization_oid: None,
                client_authentication_mode: None,
                claims: None,
                management: None,
            }),
            Utc::now() + Duration::hours(1),
        )
        .await
        .unwrap();
    let issuer = service.provider_service.issuer().unwrap();
    let (key_id, private_key_pem, alg) = service.load_signing_key().await.unwrap();
    let token_id = identity_domain::openid_connect::identifier::access_token_id(record.oid);
    let client_id = identity_domain::openid_connect::identifier::client_id(Uuid::nil());
    let resources = vec!["urn:identity:graphql".to_owned()];
    let client = service
        .client_repo
        .find_by_oid(Uuid::nil())
        .await
        .unwrap()
        .unwrap();
    let token = service
        .sign_access_token(SignAccessTokenInput {
            resources: &resources,
            token_id: &token_id,
            key_id: &key_id,
            private_key_pem: &private_key_pem,
            alg,
            issuer: &issuer,
            audience: "urn:identity:graphql",
            client_id: &client_id,
            subject: &client_id,
            principal: AccessTokenPrincipal::Client,
            client: &client,
            user: None,
            protected_session_id: None,
            scope: "account.read",
            auth_time: None,
            acr: None,
            amr: &[],
        })
        .await
        .unwrap();

    let result = service.introspect_token(request(token)).await.unwrap();
    assert_eq!(result["active"], true);
    assert_eq!(result["sub"], client_id);
    assert_eq!(result["scope"], "account.read");
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
