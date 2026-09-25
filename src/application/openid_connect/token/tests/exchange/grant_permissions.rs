use crate::openid_connect::token::tests::fixtures::*;
use crate::openid_connect::token::tests::*;
use identity_domain::auth::SessionOid;
use identity_domain::openid_connect::GrantType;

fn refresh_token_data(user_oid: Uuid) -> RefreshTokenData {
    RefreshTokenData {
        scope: "openid offline_access".to_string(),
        user_oid: user_oid.to_string(),
        session_oid: Some(SessionOid::from(Uuid::new_v4())),
        protected_session_id: None,
        auth_time: None,
        acr: None,
        amr: vec!["pwd".to_owned()],
        rotated_from: None,
        authorization_code_oid: None,
        device_authorization_oid: None,
    }
}

#[tokio::test]
async fn code_exchange_rejects_client_without_authorization_code_grant() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service_with_client_repo(
        repo.clone(),
        user_oid,
        Arc::new(RestrictedGrantClientRepository {
            grant_types: vec![GrantType::RefreshToken],
        }),
    );

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                scope: "openid offline_access".to_string(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_string(),
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let error = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24061);
    let stored = repo.find_by_oid(record.oid).await.unwrap().unwrap();
    assert!(
        stored.revoked_at.is_none(),
        "a rejected grant must not consume the authorization code"
    );
}

#[tokio::test]
async fn code_exchange_does_not_issue_unusable_refresh_token() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service_with_client_repo(
        repo.clone(),
        user_oid,
        Arc::new(RestrictedGrantClientRepository {
            grant_types: vec![GrantType::AuthorizationCode],
        }),
    );
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                scope: "openid offline_access".to_owned(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                acr: None,
                amr: vec!["pwd".to_owned()],
                auth_time: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                claims: None,
            }),
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

    let response = service
        .exchange_authorization_code(AuthorizationCodeGrantParams {
            code: STANDARD.encode(record.oid.as_bytes()),
            redirect_uri: Some("https://client.example.com/callback".to_owned()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
        })
        .await
        .unwrap();
    assert!(response.refresh_token.is_none());
}

#[tokio::test]
async fn refresh_exchange_rejects_client_without_refresh_token_grant() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service_with_client_repo(
        repo.clone(),
        user_oid,
        Arc::new(RestrictedGrantClientRepository {
            grant_types: vec![GrantType::AuthorizationCode],
        }),
    );

    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::RefreshToken(refresh_token_data(user_oid)),
            Utc::now() + chrono::Duration::days(1),
        )
        .await
        .unwrap();

    let error = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            scope: None,
            refresh_token: STANDARD.encode(record.oid.as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), 24061);
    let stored = repo.find_by_oid(record.oid).await.unwrap().unwrap();
    assert!(
        stored.revoked_at.is_none(),
        "a rejected grant must not consume the refresh token"
    );
}

#[tokio::test]
async fn grant_permission_is_checked_before_the_refresh_token_lookup() {
    // The device-only client holds no refresh grant; an unknown refresh token
    // must report the grant violation rather than invalid_grant, which keeps
    // the check independent from stored token state.
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let service = build_token_service_with_client_repo(
        repo.clone(),
        user_oid,
        Arc::new(RestrictedGrantClientRepository {
            grant_types: vec![GrantType::DeviceCode],
        }),
    );

    let error = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            scope: None,
            refresh_token: STANDARD.encode(Uuid::new_v4().as_bytes()),
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_string()),
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        24061,
        "grant permission is checked before the token is looked up"
    );
}
