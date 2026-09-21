use super::*;
use crate::database::entity::{login, session, user};
use identity_domain::auth::SessionOid;
use identity_domain::client_authorization::DeviceRequestStatus;
use sea_orm::{ConnectOptions, Database};

async fn database() -> DatabaseConnection {
    let url = std::env::var("IDENTITY_TEST_DATABASE_URL").expect("isolated test database URL");
    let db = Database::connect(ConnectOptions::new(url))
        .await
        .expect("connect test database");
    crate::database::migrate(&db)
        .await
        .expect("migrate test database");
    db
}

async fn fixture(db: &DatabaseConnection) -> (Uuid, String, login::Model, session::Model) {
    let now = Utc::now();
    let oid = Uuid::new_v4();
    let client = client::ActiveModel {
        oid: Set(oid),
        protocol: Set("openid_connect".to_owned()),
        name: Set("Device claim regression".to_owned()),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("insert client");
    let name = format!("claim-{oid}");
    let user = user::ActiveModel {
        oid: Set(Uuid::new_v4()),
        name: Set(name.clone()),
        name_normalized: Set(name.clone()),
        email: Set(format!("{name}@example.test")),
        email_normalized: Set(format!("{name}@example.test")),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("insert user");
    let session = session::ActiveModel {
        oid: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        status: Set("active".to_owned()),
        amr: Set(serde_json::json!(["pwd"])),
        authenticated_at: Set(Some(now.into())),
        last_active_at: Set(now.into()),
        expires_at: Set((now + chrono::Duration::hours(1)).into()),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("insert session");
    let code = format!("claim-{oid}");
    let data: DeviceAuthorizationRequestData = serde_json::from_value(serde_json::json!({
        "scope": "openid",
        "device_code_digest": oid.to_string(),
        "user_code": code,
        "user_code_display": code,
        "interval_seconds": 5,
        "status": "pending"
    }))
    .expect("request data");
    let repo = DeviceAuthorizationRepositoryImpl::new(db.clone());
    let request = repo
        .create_device_request(client.oid, data, now + chrono::Duration::minutes(10))
        .await
        .expect("create request");
    let row = client_authorization::Entity::find()
        .filter(client_authorization::Column::Oid.eq(request.oid))
        .one(db)
        .await
        .expect("query request")
        .expect("request exists");
    let login = login::ActiveModel {
        oid: Set(Uuid::new_v4()),
        client_id: Set(client.id),
        client_authorization_id: Set(row.id),
        status: Set(identity_domain::auth::LoginStatus::CREATED.to_string()),
        expires_at: Set((now + chrono::Duration::minutes(10)).into()),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("insert login");
    (request.oid, code, login, session)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn login_completion_consumes_user_code_and_binds_session_before_consent() {
    let db = database().await;
    let repo = DeviceAuthorizationRepositoryImpl::new(db.clone());
    let (request_oid, code, login, session) = fixture(&db).await;
    assert!(
        repo.find_active_device_request_by_user_code(&code)
            .await
            .expect("lookup code")
            .is_some()
    );
    assert!(
        repo.claim_device_request(request_oid, login.oid, SessionOid(session.oid), Utc::now())
            .await
            .expect("claim request")
    );
    assert!(
        repo.find_active_device_request_by_user_code(&code)
            .await
            .expect("lookup consumed code")
            .is_none()
    );
    let bound = login::Entity::find_by_id(login.id)
        .one(&db)
        .await
        .expect("load login")
        .expect("login exists");
    assert_eq!(bound.session_id, Some(session.id));
    assert_eq!(bound.user_id, Some(session.user_id));
    assert_eq!(bound.status, "authenticated");
    let stored = repo
        .find_device_request_by_oid(request_oid)
        .await
        .expect("load request")
        .expect("request exists");
    assert!(stored.completed_at.is_none());
    let ClientAuthorizationData::DeviceAuthorizationRequest(data) = stored.data else {
        panic!("device request")
    };
    assert_eq!(data.claimed_login_oid, Some(login.oid));
    assert_eq!(data.status, DeviceRequestStatus::Pending);
    assert!(data.approval.is_none());
    assert!(data.decided_at.is_none());
    assert!(
        repo.find_device_request_by_device_code_digest(&data.device_code_digest)
            .await
            .expect("device remains pollable")
            .is_some()
    );
    assert!(
        repo.claim_device_request(request_oid, login.oid, SessionOid(session.oid), Utc::now())
            .await
            .expect("same claim retry")
    );
    let mut other: login::ActiveModel = login.clone().into();
    other.id = Default::default();
    other.oid = Set(Uuid::new_v4());
    let other = other.insert(&db).await.expect("competing login");
    assert!(
        !repo
            .claim_device_request(request_oid, other.oid, SessionOid(session.oid), Utc::now())
            .await
            .expect("reject competing claim")
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn concurrent_device_login_claims_have_one_winner() {
    let db = database().await;
    let repo = DeviceAuthorizationRepositoryImpl::new(db.clone());
    let (request_oid, code, first, session) = fixture(&db).await;
    let mut second: login::ActiveModel = first.clone().into();
    second.id = Default::default();
    second.oid = Set(Uuid::new_v4());
    let second = second.insert(&db).await.expect("second login");
    let (a, b) = tokio::join!(
        repo.claim_device_request(request_oid, first.oid, SessionOid(session.oid), Utc::now()),
        repo.claim_device_request(request_oid, second.oid, SessionOid(session.oid), Utc::now())
    );
    assert_ne!(a.expect("first claim"), b.expect("second claim"));
    assert!(
        repo.find_active_device_request_by_user_code(&code)
            .await
            .expect("consumed code")
            .is_none()
    );
    let a = login::Entity::find_by_id(first.id)
        .one(&db)
        .await
        .expect("first login")
        .expect("exists");
    let b = login::Entity::find_by_id(second.id)
        .one(&db)
        .await
        .expect("second login")
        .expect("exists");
    assert_ne!(a.session_id.is_some(), b.session_id.is_some());
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn expired_device_login_claim_does_not_bind_or_consume() {
    let db = database().await;
    let repo = DeviceAuthorizationRepositoryImpl::new(db.clone());
    let (request_oid, _, login, session) = fixture(&db).await;
    assert!(
        !repo
            .claim_device_request(
                request_oid,
                login.oid,
                SessionOid(session.oid),
                Utc::now() + chrono::Duration::hours(2)
            )
            .await
            .expect("reject expired claim")
    );
    let bound = login::Entity::find_by_id(login.id)
        .one(&db)
        .await
        .expect("load login")
        .expect("exists");
    assert!(bound.session_id.is_none());
    let stored = repo
        .find_device_request_by_oid(request_oid)
        .await
        .expect("load request")
        .expect("exists");
    let ClientAuthorizationData::DeviceAuthorizationRequest(data) = stored.data else {
        panic!("device request")
    };
    assert!(data.claimed_login_oid.is_none());
    assert_eq!(data.status, DeviceRequestStatus::Pending);
}
