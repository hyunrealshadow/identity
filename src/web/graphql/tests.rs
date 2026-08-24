use std::sync::Arc;

use chrono::{Duration, Utc};
use http::StatusCode;
use identity_domain::{
    auth::{SessionOid, password::PasswordHashSetting},
    client_authorization::{AccessTokenData, ClientAuthorizationType},
    key::{
        KeyData, KeyType,
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
        model::AsymmetricKeyAlgorithm,
    },
    openid_connect::model::claim::{JwtClaimNames, JwtTokenType, TokenUseValues},
    setting::{
        consent_url::ConsentUrlSetting,
        dynamic_registration::DynamicClientRegistrationSetting,
        installation::{
            InstallationDomainSetting, InstallationFirstKeyOidSetting,
            InstallationFirstUserOidSetting, InstallationInitializedAtSetting,
            InstallationInitializedSetting,
        },
        login_url::LoginUrlSetting,
        model::SettingDefinition,
    },
};
use identity_infrastructure::{
    AppContext, AppLifecycle, AppResources, AppState,
    config::{AppEnvironment, GraphqlConfig, HealthChecksConfig},
    crypto::key::AsymmetricKeyGeneratorImpl,
    database::entity::{client, client_authorization, key, setting, user},
    graphql::id::{GlobalId, GlobalIdType},
    services::AppServices,
    settings::AppRuntimeSettings,
    web::tera::{build_i18n, build_tera},
};
use josekit::{
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};
use sea_orm::{DatabaseBackend, MockDatabase};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{RESOURCE_AUDIENCE, router};

struct UserGlobalId;

impl GlobalIdType for UserGlobalId {
    const TYPE_NAME: &'static str = "User";
}

struct GraphqlFixture {
    service: Service,
    token: String,
}

struct FixtureOptions<'a> {
    audience: &'a str,
    scope: &'a str,
    revoked: bool,
}

impl Default for FixtureOptions<'static> {
    fn default() -> Self {
        Self {
            audience: RESOURCE_AUDIENCE,
            scope: "openid account.read",
            revoked: false,
        }
    }
}

#[tokio::test]
async fn graphql_http_accepts_a_valid_resource_access_token() {
    let fixture = fixture(FixtureOptions::default()).await;
    let mut response = graphql_post(
        &fixture,
        "query { viewer { account { id username email birthdate } } }",
    )
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["data"]["viewer"]["account"]["username"], "ada");
    assert!(body["data"]["viewer"]["account"]["birthdate"].is_null());
    assert!(body.get("errors").is_none());
}

#[tokio::test]
async fn graphql_http_rejects_a_token_for_another_audience() {
    let fixture = fixture(FixtureOptions {
        audience: "https://api.example.com",
        ..FixtureOptions::default()
    })
    .await;
    let mut response = graphql_post(&fixture, "query { viewer { account { id } } }").await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    assert!(
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some()
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["errors"][0]["message"], "invalid access token");
}

#[tokio::test]
async fn graphql_http_rejects_a_revoked_access_token() {
    let fixture = fixture(FixtureOptions {
        revoked: true,
        ..FixtureOptions::default()
    })
    .await;
    let response = graphql_post(&fixture, "query { viewer { account { id } } }").await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn graphql_http_reports_the_required_scope() {
    let fixture = fixture(FixtureOptions {
        scope: "openid",
        ..FixtureOptions::default()
    })
    .await;
    let mut response = graphql_post(&fixture, "query { viewer { account { id } } }").await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["errors"][0]["extensions"]["requiredScope"],
        "account.read"
    );
    assert!(body["data"]["viewer"]["account"].is_null());
}

#[tokio::test]
async fn graphql_http_hides_nodes_owned_by_another_user() {
    let fixture = fixture(FixtureOptions::default()).await;
    let foreign_id = GlobalId::<UserGlobalId>::new(Uuid::new_v4()).encode();
    let query = format!("query {{ node(id: \"{foreign_id}\") {{ id }} }}");
    let mut response = graphql_post(&fixture, &query).await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert!(body["data"]["node"].is_null());
}

#[tokio::test]
async fn graphql_http_rejects_get_mutations_before_execution() {
    let fixture = fixture(FixtureOptions::default()).await;
    let query = "mutation { revokeOtherSessions { revokedCount } }";
    let response = TestClient::get("http://identity.test/graphql")
        .query("query", query)
        .bearer_auth(&fixture.token)
        .send(&fixture.service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
}

#[tokio::test]
async fn graphql_http_allows_authenticated_get_queries() {
    let fixture = fixture(FixtureOptions::default()).await;
    let mut response = TestClient::get("http://identity.test/graphql")
        .query("query", "query { viewer { account { username } } }")
        .bearer_auth(&fixture.token)
        .send(&fixture.service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["data"]["viewer"]["account"]["username"], "ada");
}

#[tokio::test]
async fn graphql_http_requires_a_bearer_token() {
    let fixture = fixture(FixtureOptions::default()).await;
    let response = TestClient::post("http://identity.test/graphql")
        .json(&json!({ "query": "query { viewer { account { id } } }" }))
        .send(&fixture.service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn graphql_http_rejects_an_unconfigured_origin() {
    let fixture = fixture(FixtureOptions::default()).await;
    let response = TestClient::post("http://identity.test/graphql")
        .add_header("origin", "https://evil.example.com", true)
        .bearer_auth(&fixture.token)
        .json(&json!({ "query": "query { viewer { account { id } } }" }))
        .send(&fixture.service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
}

async fn graphql_post(fixture: &GraphqlFixture, query: &str) -> salvo::Response {
    TestClient::post("http://identity.test/graphql")
        .bearer_auth(&fixture.token)
        .json(&json!({ "query": query }))
        .send(&fixture.service)
        .await
}

async fn fixture(options: FixtureOptions<'_>) -> GraphqlFixture {
    let now = Utc::now();
    let user_oid = Uuid::new_v4();
    let client_oid = Uuid::new_v4();
    let session_oid = Uuid::new_v4();
    let token_oid = Uuid::new_v4();
    let key_oid = Uuid::new_v4();
    let key_data = AsymmetricKeyGeneratorImpl
        .generate(&AsymmetricKeySpec {
            algorithm: AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
        })
        .unwrap();
    let key_model = key::Model {
        id: 1,
        oid: key_oid,
        r#type: KeyType::Asymmetric.to_string(),
        data: serde_json::to_value(KeyData::Asymmetric(key_data.clone())).unwrap(),
        expires_at: (now + Duration::days(1)).into(),
        revoked_at: None,
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let client_model = client::Model {
        id: 2,
        oid: client_oid,
        protocol: "openid_connect".to_owned(),
        name: "Login".to_owned(),
        names: None,
        description: None,
        built_in: false,
        created_at: now.naive_utc(),
        updated_at: None,
    };
    let access_token_model = client_authorization::Model {
        id: 3,
        oid: token_oid,
        client_id: client_model.id,
        r#type: ClientAuthorizationType::AccessToken.to_string(),
        data: serde_json::to_value(AccessTokenData {
            scope: options.scope.to_owned(),
            user_oid: user_oid.to_string(),
            session_oid: SessionOid(session_oid),
            protected_session_id: Some("protected-session".to_owned()),
            authorization_code_oid: None,
        })
        .unwrap(),
        expires_at: (now + Duration::hours(1)).into(),
        completed_at: None,
        revoked_at: options.revoked.then(|| now.into()),
        created_at: now.into(),
        updated_at: None,
    };
    let user_model = test_user(user_oid, now);
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(setting_rows(user_oid, key_oid, now))
        .append_query_results([
            Vec::<key::Model>::new(),
            Vec::<key::Model>::new(),
            vec![key_model],
        ])
        .append_query_results([[((access_token_model), client_model)]])
        .append_query_results([[user_model]])
        .into_connection();
    let i18n = build_i18n().unwrap();
    let tera = build_tera(i18n.loader()).unwrap();
    let settings = Arc::new(AppRuntimeSettings::from_db(db.clone()).await.unwrap());
    let services = Arc::new(AppServices::from_db(db.clone(), settings.as_ref()).unwrap());
    let state = AppState::new(
        Arc::new(AppContext::new(
            AppEnvironment::Test,
            HealthChecksConfig::default(),
        )),
        Arc::new(AppResources::new(db, tera, i18n)),
        Arc::new(AppLifecycle::new()),
        settings,
        services,
    );
    let config = GraphqlConfig::default();
    let token = access_token(
        &key_data.private_key,
        key_oid,
        token_oid,
        user_oid,
        client_oid,
        options.audience,
        options.scope,
    );

    GraphqlFixture {
        service: Service::new(router(state, &config)),
        token,
    }
}

fn access_token(
    private_key: &str,
    key_oid: Uuid,
    token_oid: Uuid,
    user_oid: Uuid,
    client_oid: Uuid,
    audience: &str,
    scope: &str,
) -> String {
    let now = std::time::SystemTime::now();
    let mut header = JwsHeader::new();
    header.set_token_type(JwtTokenType::ACCESS_TOKEN);
    header.set_key_id(key_oid.to_string());
    let mut payload = JwtPayload::new();
    payload.set_issuer("https://identity.example.com/");
    payload.set_subject(user_oid.to_string());
    payload.set_audience(vec![audience]);
    payload.set_issued_at(&now);
    payload.set_expires_at(&(now + std::time::Duration::from_secs(3600)));
    payload.set_jwt_id(token_oid.to_string());
    payload
        .set_claim(JwtClaimNames::CLIENT_ID, Some(json!(client_oid)))
        .unwrap();
    payload
        .set_claim(JwtClaimNames::SCOPE, Some(json!(scope)))
        .unwrap();
    payload
        .set_claim(JwtClaimNames::SID, Some(json!("protected-session")))
        .unwrap();
    payload
        .set_claim(
            JwtClaimNames::TOKEN_USE,
            Some(json!(TokenUseValues::ACCESS_TOKEN)),
        )
        .unwrap();
    let signer = RS256.signer_from_pem(private_key.as_bytes()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

fn setting_rows(
    user_oid: Uuid,
    key_oid: Uuid,
    now: chrono::DateTime<Utc>,
) -> Vec<Vec<setting::Model>> {
    vec![
        vec![setting_model::<InstallationInitializedSetting>(
            1, true, now,
        )],
        vec![setting_model::<InstallationDomainSetting>(
            2,
            Some("identity.example.com".to_owned()),
            now,
        )],
        vec![setting_model::<InstallationFirstUserOidSetting>(
            3,
            Some(user_oid),
            now,
        )],
        vec![setting_model::<InstallationFirstKeyOidSetting>(
            4,
            Some(key_oid),
            now,
        )],
        vec![setting_model::<InstallationInitializedAtSetting>(
            5,
            Some(now),
            now,
        )],
        vec![setting_model::<PasswordHashSetting>(
            6,
            PasswordHashSetting::default_value(),
            now,
        )],
        vec![setting_model::<DynamicClientRegistrationSetting>(
            7,
            DynamicClientRegistrationSetting::default_value(),
            now,
        )],
        vec![setting_model::<LoginUrlSetting>(
            8,
            LoginUrlSetting::default_value(),
            now,
        )],
        vec![setting_model::<ConsentUrlSetting>(
            9,
            ConsentUrlSetting::default_value(),
            now,
        )],
    ]
}

fn setting_model<S>(id: i32, value: S::Value, now: chrono::DateTime<Utc>) -> setting::Model
where
    S: SettingDefinition,
{
    setting::Model {
        id,
        oid: Uuid::new_v4(),
        key: S::KEY.to_owned(),
        value: serde_json::to_value(value).unwrap(),
        created_at: now.naive_utc(),
        updated_at: None,
    }
}

fn test_user(oid: Uuid, now: chrono::DateTime<Utc>) -> user::Model {
    user::Model {
        id: 10,
        oid,
        name: "ada".to_owned(),
        name_normalized: "ada".to_owned(),
        email: "ada@example.com".to_owned(),
        email_normalized: "ada@example.com".to_owned(),
        email_verified: true,
        phone_number: None,
        phone_number_verified: None,
        nickname: None,
        given_name: Some("Ada".to_owned()),
        family_name: Some("Lovelace".to_owned()),
        middle_name: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zone_info: None,
        locale: None,
        preferences: serde_json::json!({}),
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        failed_attempts: 0,
        enabled: true,
        locked: false,
        locked_until: None,
        created_at: now.into(),
        updated_at: None,
    }
}
