use super::*;
use crate::error::code::AppErrorCode;
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
async fn unknown_token_succeeds_after_client_authentication() {
    let service =
        fixtures::build_token_service(Arc::new(fixtures::mock_client_auth_repo()), Uuid::new_v4());
    service
        .revoke_token(request("unknown-token".to_owned()))
        .await
        .unwrap();
}

#[tokio::test]
async fn refresh_token_revokes_its_grant() {
    let mut repo = fixtures::mock_client_auth_repo();
    repo.expect_revoke_refresh_grant_for_client()
        .times(1)
        .returning(|_, _, _| Ok(()));
    let repo = Arc::new(repo);
    let service = fixtures::build_token_service(repo.clone(), Uuid::new_v4());
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::RefreshToken(RefreshTokenData {
                scope: "openid offline_access".to_owned(),
                user_oid: Uuid::new_v4().to_string(),
                session_oid: None,
                protected_session_id: None,
                auth_time: None,
                acr: None,
                amr: vec![],
                rotated_from: None,
                authorization_code_oid: None,
                device_authorization_oid: None,
            }),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    let token = STANDARD.encode(record.oid.as_bytes());
    service.revoke_token(request(token)).await.unwrap();
}

#[tokio::test]
async fn another_clients_refresh_token_is_rejected() {
    let repo = Arc::new(fixtures::mock_client_auth_repo());
    let service = fixtures::build_token_service(repo.clone(), Uuid::new_v4());
    let record = repo
        .create(
            Uuid::new_v4(),
            ClientAuthorizationData::RefreshToken(RefreshTokenData {
                scope: "offline_access".to_owned(),
                user_oid: Uuid::new_v4().to_string(),
                session_oid: None,
                protected_session_id: None,
                auth_time: None,
                acr: None,
                amr: vec![],
                rotated_from: None,
                authorization_code_oid: None,
                device_authorization_oid: None,
            }),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    let error = service
        .revoke_token(request(STANDARD.encode(record.oid.as_bytes())))
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        crate::error::codes::token::TokenErrorCode::RefreshTokenClientMismatch.code()
    );
}

#[tokio::test]
async fn signed_access_token_revokes_only_its_record() {
    let mut repo = fixtures::mock_client_auth_repo();
    repo.expect_revoke_access_token_for_client()
        .times(1)
        .returning(|_, _, _| Ok(()));
    let repo = Arc::new(repo);
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
    service
        .revoke_token(request(format!("{token}x")))
        .await
        .unwrap();
    service.revoke_token(request(token)).await.unwrap();
}
