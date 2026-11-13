//! Live human session, user-state and device-relation enforcement.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use identity_domain::{
    auth::{SessionOid, SessionStatus, model::Session},
    client_authorization::{AuthorizationCodeData, ClientAuthorizationData, RefreshTokenData},
};
use uuid::Uuid;

use crate::openid_connect::{
    tests::fixtures::mocks::session::MockSessionRepository,
    token::tests::{fixtures::*, *},
};

fn session(
    session_oid: SessionOid,
    user_oid: Uuid,
    status: SessionStatus,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
) -> Session {
    Session {
        oid: session_oid,
        user_oid,
        status,
        device_name: None,
        device_type: None,
        os_name: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
        user_agent: None,
        ip_address: None,
        last_active_at: None,
        expires_at,
        revoked_at,
        created_at: Utc::now(),
        acr: None,
        acr_expires_at: None,
        amr: Vec::new(),
    }
}

fn active_session(session_oid: SessionOid, user_oid: Uuid) -> Session {
    session(session_oid, user_oid, SessionStatus::Active, None, None)
}

async fn authorization_code_for(
    repo: &Arc<MockClientAuthorizationRepository>,
    user_oid: Uuid,
    session_oid: SessionOid,
) -> Uuid {
    repo.create(
        Uuid::nil(),
        ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
            resources: Vec::new(),
            scope: "openid profile".to_owned(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            user_oid: user_oid.to_string(),
            session_oid,
            protected_session_id: None,
            acr: None,
            amr: vec![],
            auth_time: None,
            redirect_uri: "https://client.example.com/callback".to_owned(),
            redirect_uri_was_supplied: true,
            management: None,
            claims: None,
        }),
        Utc::now() + Duration::minutes(10),
    )
    .await
    .unwrap()
    .oid
}

fn code_params(oid: Uuid) -> AuthorizationCodeGrantParams {
    AuthorizationCodeGrantParams {
        resources: Vec::new(),
        code: STANDARD.encode(oid.as_bytes()),
        redirect_uri: Some("https://client.example.com/callback".to_owned()),
        client_id: Some(identity_domain::openid_connect::identifier::client_id(
            Uuid::nil(),
        )),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
        code_verifier: None,
    }
}

async fn assert_code_session_rejected(session_result: Option<Session>, expected_code: u32) {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let session_oid = SessionOid::from(Uuid::new_v4());
    let code_oid = authorization_code_for(&repo, user_oid, session_oid).await;

    let mut mock = MockSessionRepository::new();
    let result = session_result.clone();
    mock.expect_find_by_oid()
        .returning(move |_| Ok(result.clone()));
    let service = build_token_service(repo.clone(), user_oid).with_session_repo(Arc::new(mock));

    let error = service
        .exchange_authorization_code(code_params(code_oid))
        .await
        .unwrap_err();
    assert_eq!(error.code(), expected_code);
    assert!(
        repo.find_by_oid(code_oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none(),
        "a rejected session must not consume the authorization code"
    );
}

#[tokio::test]
async fn authorization_code_requires_a_matching_live_session() {
    let user_oid = Uuid::new_v4();
    let session_oid = SessionOid::from(Uuid::new_v4());

    assert_code_session_rejected(None, 24054).await;
    assert_code_session_rejected(
        Some(session(
            session_oid,
            user_oid,
            SessionStatus::Active,
            None,
            Some(Utc::now()),
        )),
        24056,
    )
    .await;
    assert_code_session_rejected(
        Some(session(
            session_oid,
            user_oid,
            SessionStatus::Active,
            Some(Utc::now() - Duration::seconds(1)),
            None,
        )),
        24057,
    )
    .await;
    assert_code_session_rejected(Some(active_session(session_oid, Uuid::new_v4())), 24058).await;
}

#[tokio::test]
async fn authorization_code_rejects_disabled_and_locked_users() {
    for (enabled, locked) in [(false, false), (true, true)] {
        let repo = Arc::new(mock_client_auth_repo());
        let user_oid = Uuid::new_v4();
        let session_oid = SessionOid::from(Uuid::new_v4());
        let code_oid = authorization_code_for(&repo, user_oid, session_oid).await;

        let mut service = build_token_service(repo, user_oid);
        let mut user = test_user(user_oid);
        user.enabled = enabled;
        user.locked = locked;
        service.user_repo = Arc::new(InMemoryUserRepository { user });

        let error = service
            .exchange_authorization_code(code_params(code_oid))
            .await
            .unwrap_err();
        assert_eq!(error.code(), 24011);
    }
}

fn refresh_params(oid: Uuid) -> RefreshTokenGrantParams {
    RefreshTokenGrantParams {
        resources: Vec::new(),
        scope: None,
        refresh_token: STANDARD.encode(oid.as_bytes()),
        client_id: Some(identity_domain::openid_connect::identifier::client_id(
            Uuid::nil(),
        )),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    }
}

async fn refresh_record_for(
    repo: &Arc<MockClientAuthorizationRepository>,
    user_oid: Uuid,
    session_oid: Option<SessionOid>,
    device_authorization_oid: Option<String>,
) -> Uuid {
    repo.create(
        Uuid::nil(),
        ClientAuthorizationData::RefreshToken(RefreshTokenData {
            resources: Vec::new(),
            scope: "openid offline_access".to_owned(),
            user_oid: user_oid.to_string(),
            session_oid,
            protected_session_id: None,
            auth_time: None,
            acr: None,
            amr: vec![],
            rotated_from: None,
            authorization_code_oid: None,
            device_authorization_oid,
            client_authentication_mode: None,
            management: None,
        }),
        Utc::now() + Duration::days(30),
    )
    .await
    .unwrap()
    .oid
}

async fn assert_refresh_session_rejected(session_result: Option<Session>) {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let session_oid = SessionOid::from(Uuid::new_v4());
    let refresh_oid = refresh_record_for(&repo, user_oid, Some(session_oid), None).await;

    let mut mock = MockSessionRepository::new();
    let result = session_result.clone();
    mock.expect_find_by_oid()
        .returning(move |_| Ok(result.clone()));
    let service = build_token_service(repo.clone(), user_oid).with_session_repo(Arc::new(mock));

    let error = service
        .exchange_refresh_token(refresh_params(refresh_oid))
        .await
        .unwrap_err();
    assert_eq!(error.code(), 24015);
    assert!(
        repo.find_by_oid(refresh_oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none(),
        "a rejected session must not consume the refresh token"
    );
}

#[tokio::test]
async fn refresh_requires_a_matching_live_session_for_human_tokens() {
    let user_oid = Uuid::new_v4();
    let session_oid = SessionOid::from(Uuid::new_v4());

    assert_refresh_session_rejected(None).await;
    assert_refresh_session_rejected(Some(session(
        session_oid,
        user_oid,
        SessionStatus::Active,
        Some(Utc::now() - Duration::seconds(1)),
        None,
    )))
    .await;
    assert_refresh_session_rejected(Some(session(
        session_oid,
        user_oid,
        SessionStatus::Active,
        None,
        Some(Utc::now()),
    )))
    .await;
    assert_refresh_session_rejected(Some(active_session(session_oid, Uuid::new_v4()))).await;
}

#[tokio::test]
async fn refresh_without_a_session_is_rejected_unless_it_is_device_linked() {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let refresh_oid = refresh_record_for(&repo, user_oid, None, None).await;
    let mut session_repo = MockSessionRepository::new();
    session_repo.expect_find_by_oid().returning(|_| Ok(None));
    let service = build_token_service(repo, user_oid).with_session_repo(Arc::new(session_repo));

    let error = service
        .exchange_refresh_token(refresh_params(refresh_oid))
        .await
        .unwrap_err();
    assert_eq!(error.code(), 24015);
}

#[tokio::test]
async fn refresh_rejects_disabled_or_locked_users_without_consuming_the_token() {
    for (enabled, locked) in [(false, false), (true, true)] {
        let repo = Arc::new(mock_client_auth_repo());
        let user_oid = Uuid::new_v4();
        let refresh_oid = refresh_record_for(&repo, user_oid, None, None).await;

        let mut user = test_user(user_oid);
        user.enabled = enabled;
        user.locked = locked;
        let mut service = build_token_service(repo.clone(), user_oid);
        service.user_repo = Arc::new(InMemoryUserRepository { user });

        let error = service
            .exchange_refresh_token(refresh_params(refresh_oid))
            .await
            .unwrap_err();
        assert_eq!(error.code(), 24022);
        assert!(
            repo.find_by_oid(refresh_oid)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
    }
}
