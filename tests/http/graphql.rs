use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration as TimeDuration, SystemTime},
};

use chrono::{DateTime, Duration, Utc};
use http::{StatusCode, header::WWW_AUTHENTICATE};
use identity_application::setting::{
    DeviceAuthorizationSettings, DomainSetting, LoginDomainSetting, PasswordHashSetting,
    SettingDefinition,
};
use identity_domain::{
    auth::SessionOid,
    client_authorization::{AccessTokenData, ClientAuthorizationType},
    key::{
        KeyData, KeyType,
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
        model::AsymmetricKeyAlgorithm,
    },
    openid_connect::model::claim::{JwtClaimNames, JwtTokenType, TokenUse},
};
use identity_infrastructure::{
    AppContext, AppLifecycle, AppResources, AppState,
    config::{AppEnvironment, GraphqlConfig, HealthChecksConfig},
    crypto::key::AsymmetricKeyGeneratorImpl,
    database::entity::{
        client, client_authorization, client_openid_connect::Model as ClientOpenIdConnectModel,
        client_openid_connect_platform::Model as ClientOpenIdConnectPlatformModel, key,
        resource::Model as ResourceModel, session::Model as SessionModel, setting, user,
    },
    services::AppServices,
    settings::AppRuntimeSettings,
    web::tera::{build_i18n, build_tera},
};
use josekit::{
    jws::{JwsHeader, RS256},
    jwt,
    jwt::JwtPayload,
};
use salvo::{
    Response, Service,
    test::{ResponseExt, TestClient},
};
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Value as SeaOrmValue};
use serde_json::{Value, json, to_value};
use uuid::Uuid;

use identity_domain::{
    client_authorization::AccessTokenPrincipal,
    openid_connect::{API_RESOURCE as RESOURCE_AUDIENCE, ScopeSet},
};
use identity_web::graphql::router;

use identity_domain::global_id::{
    GlobalId,
    kind::{Client as ClientGlobalId, Resource as ResourceGlobalId, User as UserGlobalId},
};

struct GraphqlFixture {
    service: Service,
    token: String,
}

/// Which post-validation reads a test will issue.
///
/// The shared prelude (transport validation plus the handler's account lookup)
/// is identical for every request. Management authority, effective permissions
/// and node ownership are read only by the fields that need them, so those
/// tails must be supplied per shape rather than guessed.
#[derive(Clone, Copy)]
enum FixtureTail {
    /// Ordinary self-service field that stops after the handler account lookup.
    SelfService,
    /// `node(id:)` for a foreign user: current authority, target owner check and
    /// the semantic policy fingerprint.
    NodeRead,
    /// `effectivePermissions`: authority and the live GraphQL resource scopes.
    EffectivePermissions,
    /// RBAC field guard for an ordinary user: live authority and fingerprint.
    ManagementDenial,
}

struct FixtureOptions {
    audience: &'static str,
    scope: &'static str,
    revoked: bool,
    tail: FixtureTail,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            audience: RESOURCE_AUDIENCE,
            scope: "openid account.read",
            revoked: false,
            tail: FixtureTail::SelfService,
        }
    }
}

#[tokio::test]
async fn graphql_http_accepts_a_valid_resource_access_token() {
    let fixture = fixture(FixtureOptions::default()).await;
    let mut response = graphql_post(
        &fixture,
        "query { account { id username email birthdate } }",
    )
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["data"]["account"]["username"], "ada");
    assert!(body["data"]["account"]["birthdate"].is_null());
    assert!(body.get("errors").is_none());
}

#[tokio::test]
async fn graphql_http_rejects_a_token_for_another_audience() {
    let fixture = fixture(FixtureOptions {
        audience: "https://api.example.com",
        ..FixtureOptions::default()
    })
    .await;
    let mut response = graphql_post(&fixture, "query { account { id } }").await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    assert!(response.headers().get(WWW_AUTHENTICATE).is_some());
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["errors"][0]["extensions"]["code"], 28109);
}

#[tokio::test]
async fn graphql_http_rejects_a_revoked_access_token() {
    let fixture = fixture(FixtureOptions {
        revoked: true,
        ..FixtureOptions::default()
    })
    .await;
    let response = graphql_post(&fixture, "query { account { id } }").await;

    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn graphql_http_reports_the_required_scope() {
    let fixture = fixture(FixtureOptions {
        scope: "openid",
        ..FixtureOptions::default()
    })
    .await;
    let mut response = graphql_post(&fixture, "query { account { id } }").await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["errors"][0]["extensions"]["requiredScope"],
        "account.read"
    );
    assert_eq!(
        body["errors"][0]["extensions"]["code"],
        "insufficient_scope"
    );
    assert!(body["data"]["account"].is_null());
    assert_eq!(
        body["extensions"]["requestId"],
        body["errors"][0]["extensions"]["requestId"]
    );
}

#[tokio::test]
async fn graphql_http_exposes_safe_instance_metadata() {
    let fixture = fixture(FixtureOptions::default()).await;
    let mut response = graphql_post(
        &fixture,
        "query { instanceInfo { name environment issuer version } }",
    )
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    let info = &body["data"]["instanceInfo"];
    assert_eq!(info["name"], "Identity");
    assert_eq!(info["environment"], "test");
    assert!(
        info["issuer"]
            .as_str()
            .is_some_and(|issuer| !issuer.is_empty())
    );
    assert!(
        info["version"]
            .as_str()
            .is_some_and(|version| !version.is_empty())
    );
}

#[tokio::test]
async fn graphql_http_returns_empty_management_permissions_for_an_ordinary_user() {
    let fixture = fixture(FixtureOptions {
        tail: FixtureTail::EffectivePermissions,
        ..FixtureOptions::default()
    })
    .await;
    let mut response = graphql_post(
        &fixture,
        "query { effectivePermissions { requestableScopes grantedScopes effectiveScopes authentication { acr authTime aal2 recent } } }",
    )
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    let permissions = &body["data"]["effectivePermissions"];
    assert_eq!(permissions["requestableScopes"], json!([]));
    assert_eq!(permissions["effectiveScopes"], json!([]));
    assert_eq!(permissions["grantedScopes"], json!([]));
    assert_eq!(permissions["authentication"]["aal2"], false);
    assert_eq!(permissions["authentication"]["recent"], false);
    assert!(permissions["authentication"]["acr"].is_null());
    assert!(permissions["authentication"]["authTime"].is_null());
}

#[tokio::test]
async fn graphql_http_hides_nodes_owned_by_another_user() {
    let fixture = fixture(FixtureOptions {
        tail: FixtureTail::NodeRead,
        ..FixtureOptions::default()
    })
    .await;
    let foreign_id = GlobalId::<UserGlobalId>::new(Uuid::new_v4()).encode();
    let query = format!("query {{ node(id: \"{foreign_id}\") {{ id }} }}");
    let mut response = graphql_post(&fixture, &query).await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert!(body["data"]["node"].is_null());
}

#[tokio::test]
async fn graphql_http_denies_rbac_resource_reads_without_management_authority() {
    let fixture = fixture(FixtureOptions {
        tail: FixtureTail::ManagementDenial,
        ..FixtureOptions::default()
    })
    .await;
    let mut response = graphql_post(
        &fixture,
        "query { resources { edges { node { id uri } } pageInfo { hasNextPage } } }",
    )
    .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    // The non-null connection must not leak data when its live Guard denies.
    assert!(body["data"].is_null());
    assert!(body["errors"].is_array());
}

#[tokio::test]
async fn graphql_http_collection_totals_require_management_read_authority() {
    for field in ["users", "roles", "groups", "scopes", "clients"] {
        let fixture = fixture(FixtureOptions {
            tail: FixtureTail::ManagementDenial,
            ..FixtureOptions::default()
        })
        .await;
        let mut response = graphql_post(
            &fixture,
            &format!("query {{ {field}(first: 1) {{ count: totalCount }} }}"),
        )
        .await;
        let body: Value = response.take_json().await.unwrap();
        assert!(body["data"].is_null(), "{field} leaked a collection count");
        let errors = body["errors"].as_array().unwrap();
        assert!(!errors.is_empty());
        assert!(!errors.iter().any(|error| {
            error["message"]
                .as_str()
                .unwrap_or_default()
                .contains("Unknown field")
        }));
    }
}

#[tokio::test]
async fn graphql_http_denies_rbac_writes_without_management_authority() {
    let fixture = fixture(FixtureOptions {
        tail: FixtureTail::ManagementDenial,
        ..FixtureOptions::default()
    })
    .await;
    let mutation = r#"mutation {
        createResource(input: {
            uri: "https://api.example.com/orders",
            name: "Orders",
            reason: "test denial"
        }) { resourceId version }
    }"#;
    let mut response = graphql_post(&fixture, mutation).await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert!(body["data"]["createResource"].is_null());
    assert!(body["errors"].is_array());
}

#[tokio::test]
async fn graphql_http_denies_client_management_without_management_authority() {
    let id = GlobalId::<ClientGlobalId>::new(Uuid::new_v4()).encode();
    let version = Uuid::new_v4();
    for (field, operation) in [
        (
            "client",
            format!(r#"query {{ client(id: "{id}") {{ id clientId }} }}"#),
        ),
        (
            "createClient",
            r#"mutation { createClient(input: { name: "Orders", settings: {
                platforms: [], grantTypes: [CLIENT_CREDENTIALS] } }) { clientId } }"#
                .to_owned(),
        ),
        (
            "disableClient",
            format!(
                r#"mutation {{ disableClient(input: {{ id: "{id}", expectedVersion: "{version}" }}) {{ clientId }} }}"#
            ),
        ),
        (
            "deleteClient",
            format!(
                r#"mutation {{ deleteClient(input: {{ id: "{id}", expectedVersion: "{version}" }}) {{ clientId }} }}"#
            ),
        ),
        (
            "createClientSecret",
            format!(
                r#"mutation {{ createClientSecret(input: {{ clientId: "{id}", expectedVersion: "{version}" }}) {{ secret }} }}"#
            ),
        ),
    ] {
        let fixture = fixture(FixtureOptions {
            tail: FixtureTail::ManagementDenial,
            ..FixtureOptions::default()
        })
        .await;
        let mut response = graphql_post(&fixture, &operation).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body: Value = response.take_json().await.unwrap();
        assert!(
            body["data"].is_null() || body["data"][field].is_null(),
            "{field} was not denied"
        );
        let errors = body["errors"].as_array().unwrap();
        assert!(!errors.is_empty(), "{field} returned no error");
        assert!(
            !errors.iter().any(|error| error["message"]
                .as_str()
                .unwrap_or_default()
                .contains("Unknown")),
            "{field} is not part of the schema"
        );
    }
}

#[tokio::test]
async fn graphql_http_account_permissions_requires_only_account_read() {
    let fixture = fixture(FixtureOptions {
        scope: "openid",
        ..FixtureOptions::default()
    })
    .await;
    let resource_id = GlobalId::<ResourceGlobalId>::new(Uuid::new_v4()).encode();
    let query = format!(
        "query {{ accountPermissions(resourceId: \"{resource_id}\") {{ edges {{ node {{ code }} }} }} }}"
    );
    let mut response = graphql_post(&fixture, &query).await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    let error = &body["errors"][0];
    assert_eq!(error["extensions"]["code"], "insufficient_scope");
    assert_eq!(error["extensions"]["requiredScope"], "account.read");
    assert!(body["data"].is_null());
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
        .query("query", "query { account { username } }")
        .bearer_auth(&fixture.token)
        .send(&fixture.service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["data"]["account"]["username"], "ada");
}

#[tokio::test]
async fn graphql_http_requires_a_bearer_token() {
    let fixture = fixture(FixtureOptions::default()).await;
    let response = TestClient::post("http://identity.test/graphql")
        .json(&json!({ "query": "query { account { id } }" }))
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
        .json(&json!({ "query": "query { account { id } }" }))
        .send(&fixture.service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
}

#[tokio::test]
async fn graphql_http_rejects_a_raw_uuid_session_id() {
    let fixture = fixture(FixtureOptions {
        scope: "openid session.revoke",
        ..FixtureOptions::default()
    })
    .await;
    let raw = Uuid::new_v4().to_string();
    let query = format!("mutation {{ revokeSession(id: \"{raw}\") {{ clientMutationId }} }}");
    let mut response = graphql_post(&fixture, &query).await;

    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["errors"][0]["extensions"]["code"], 28013);
    assert!(body["data"]["revokeSession"].is_null());
}

async fn graphql_post(fixture: &GraphqlFixture, query: &str) -> Response {
    TestClient::post("http://identity.test/graphql")
        .bearer_auth(&fixture.token)
        .json(&json!({ "query": query }))
        .send(&fixture.service)
        .await
}

async fn fixture(options: FixtureOptions) -> GraphqlFixture {
    let now = Utc::now();
    let user_oid = Uuid::new_v4();
    let user_version = Uuid::new_v4();
    let client_oid = Uuid::new_v4();
    let session_oid = Uuid::new_v4();
    let token_oid = Uuid::new_v4();
    let key_oid = Uuid::new_v4();
    let key_data = AsymmetricKeyGeneratorImpl
        .generate(&AsymmetricKeySpec {
            algorithm: AsymmetricKeyAlgorithm::Rsa2048,
            signing: None,
        })
        .unwrap();
    let key_model = key::Model {
        id: 1,
        oid: key_oid,
        r#type: KeyType::Asymmetric.to_string(),
        data: to_value(KeyData::Asymmetric(key_data.clone())).unwrap(),
        expires_at: (now + Duration::days(1)).into(),
        revoked_at: None,
        rotated_from_oid: None,
        rotated_at: None,
        created_at: now.into(),
        updated_at: None,
    };
    let client_model = client::Model {
        version: Uuid::new_v4(),
        id: 2,
        oid: client_oid,
        protocol: "openid_connect".to_owned(),
        name: "Login".to_owned(),
        names: None,
        description: None,
        descriptions: None,
        built_in: false,
        enabled: true,
        created_at: now.into(),
        updated_at: None,
    };
    let access_token_model = client_authorization::Model {
        id: 3,
        oid: token_oid,
        client_id: client_model.id,
        r#type: ClientAuthorizationType::AccessToken.to_string(),
        data: to_value(AccessTokenData {
            principal: AccessTokenPrincipal::User,
            management: None,
            scope: options.scope.to_owned(),
            resources: Vec::new(),
            user_oid: Some(user_oid.to_string()),
            session_oid: Some(SessionOid(session_oid)),
            protected_session_id: Some("protected-session".to_owned()),
            authorization_code_oid: None,
            refresh_token_oid: None,
            device_authorization_oid: None,
            client_authentication_mode: None,
        })
        .unwrap(),
        expires_at: (now + Duration::hours(1)).into(),
        completed_at: None,
        revoked_at: options.revoked.then(|| now.into()),
        expired: false,
        created_at: now.into(),
        updated_at: None,
    };
    let user_model = test_user(user_oid, user_version, now);
    let scope_rows = || {
        [
            "openid",
            "account.*",
            "account.read",
            "account.update",
            "session.*",
            "session.read",
            "session.revoke",
            "password.change",
        ]
        .map(|name| BTreeMap::from([("code".to_owned(), SeaOrmValue::from(name))]))
    };
    let metadata = test_metadata(client_model.id, now);
    let session = test_session(session_oid, user_model.id, now);
    // `load_user_permission_authority` returns only the permissions aggregate;
    // the authority identity is the derived semantic fingerprint read by a
    // separate dependency query, never the user record's optimistic-lock
    // version.
    let user_permission_authority_row =
        || BTreeMap::from([("permissions".to_owned(), SeaOrmValue::from(json!([])))]);
    // `user_authority_fingerprint` reads `{kind, payload}` dependency rows from
    // the same transaction. An ordinary user always has its subject row.
    let user_authority_fingerprint_rows = || {
        [BTreeMap::from([
            ("kind".to_owned(), SeaOrmValue::from("subject")),
            (
                "payload".to_owned(),
                SeaOrmValue::from(json!([user_oid, true, false, null])),
            ),
        ])]
    };
    let resource_row = || ResourceModel {
        oid: Uuid::new_v4(),
        uri: RESOURCE_AUDIENCE.to_owned(),
        name: "GraphQL".to_owned(),
        version: Uuid::new_v4(),
        enabled: true,
        created_at: now.into(),
        updated_at: None,
    };
    let rbac_resource_state_row = || {
        BTreeMap::from([
            ("resource_oid".to_owned(), SeaOrmValue::from(Uuid::new_v4())),
            (
                "resource_uri".to_owned(),
                SeaOrmValue::from(options.audience.to_owned()),
            ),
            ("resource_enabled".to_owned(), SeaOrmValue::from(true)),
        ])
    };
    // Startup reads settings, CORS origins and the symmetric/asymmetric key
    // ring. This fixture intentionally keeps signing keys out of the initial
    // ring; bearer validation reads the live asymmetric key separately.
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([setting_rows(now)])
        .append_query_results([Vec::<setting::Model>::new()])
        .append_query_results([Vec::<key::Model>::new()])
        .append_query_results([Vec::<key::Model>::new()])
        // Bearer validation: live signing keys, the joined access-token/client
        // row, the live client (metadata, platforms, exact assigned scopes),
        // the human subject and its session.
        .append_query_results([vec![key_model]])
        .append_query_results([[(access_token_model, client_model.clone())]])
        .append_query_results([[(client_model.clone(), Some(metadata))]])
        .append_query_results([Vec::<ClientOpenIdConnectPlatformModel>::new()])
        .append_query_results([scope_rows()])
        .append_query_results([[user_model.clone()]])
        .append_query_results([[(session, Some(user_model.clone()))]]);
    let db = if ScopeSet::parse(options.scope)
        .unwrap()
        .has_resource_permissions()
    {
        // Resource selection resolves the live catalog for the audience, then
        // derives the accepted-scope projection from the resource's own scope
        // rows. There is no policy row.
        let db = db
            .append_query_results([scope_rows()])
            .append_query_results([[resource_row()]])
            .append_query_results([scope_rows()]);
        if options.audience == RESOURCE_AUDIENCE {
            db
        } else {
            // A non-default business audience reads its live resource state in
            // its own repeatable-read transaction before the self-service
            // scope is rejected.
            db.append_exec_results([MockExecResult::default()])
                .append_query_results([[rbac_resource_state_row()]])
                .append_query_results([Vec::<BTreeMap<String, sea_orm::Value>>::new()])
        }
    } else {
        db
    };
    // The handler's own account lookup (relation-free repository read).
    let db = db.append_query_results([[user_model.clone()]]);
    let db = match options.tail {
        FixtureTail::SelfService => db,
        FixtureTail::NodeRead => db
            // The actor and the foreign target each open a repeatable-read
            // authority transaction, which executes the isolation statement
            // before reading the permission aggregate and dependencies.
            .append_exec_results([MockExecResult::default(), MockExecResult::default()])
            // The actor has no live management authority.
            .append_query_results([[user_permission_authority_row()]])
            .append_query_results([user_authority_fingerprint_rows()])
            // The foreign target is not a recoverable owner either.
            .append_query_results([[user_permission_authority_row()]])
            .append_query_results([user_authority_fingerprint_rows()]),
        FixtureTail::EffectivePermissions => db
            // `find_user_permission_authority` opens one repeatable-read
            // transaction and executes the isolation statement first.
            .append_exec_results([MockExecResult::default()])
            .append_query_results([[user_permission_authority_row()]])
            .append_query_results([user_authority_fingerprint_rows()])
            // The provider projects the live GraphQL resource and its owned
            // scope rows; client policy reads no longer exist.
            .append_query_results([[resource_row()]])
            .append_query_results([scope_rows()]),
        FixtureTail::ManagementDenial => db
            // The instance-targeted guard opens one repeatable-read authority
            // transaction before denying the ordinary user.
            .append_exec_results([MockExecResult::default()])
            .append_query_results([[user_permission_authority_row()]])
            .append_query_results([user_authority_fingerprint_rows()]),
    };
    let db = db.into_connection();
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
    let now = SystemTime::now();
    let mut header = JwsHeader::new();
    header.set_token_type(JwtTokenType::ACCESS_TOKEN);
    header.set_key_id(identity_domain::openid_connect::identifier::key_id(key_oid));
    let mut payload = JwtPayload::new();
    payload.set_issuer("https://identity.example.com/");
    payload.set_subject(identity_domain::openid_connect::identifier::user_subject(
        user_oid,
    ));
    payload.set_audience(vec![audience]);
    payload.set_issued_at(&now);
    payload.set_expires_at(&(now + TimeDuration::from_secs(3600)));
    payload.set_jwt_id(identity_domain::openid_connect::identifier::access_token_id(token_oid));
    payload
        .set_claim(
            JwtClaimNames::CLIENT_ID,
            Some(json!(
                identity_domain::openid_connect::identifier::client_id(client_oid)
            )),
        )
        .unwrap();
    payload
        .set_claim(JwtClaimNames::SCOPE, Some(json!(scope)))
        .unwrap();
    payload
        .set_claim(JwtClaimNames::SID, Some(json!("protected-session")))
        .unwrap();
    payload
        .set_claim(JwtClaimNames::TOKEN_USE, Some(json!(TokenUse::AccessToken)))
        .unwrap();
    let signer = RS256.signer_from_pem(private_key.as_bytes()).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

fn setting_rows(now: DateTime<Utc>) -> Vec<setting::Model> {
    vec![
        setting::Model {
            id: 1,
            oid: Uuid::new_v4(),
            key: "app.installation.initialized".to_owned(),
            value: json!(true),
            created_at: now.into(),
            updated_at: None,
        },
        setting_model::<DomainSetting>(2, Some("identity.example.com".to_owned()), now),
        setting::Model {
            id: 5,
            oid: Uuid::new_v4(),
            key: "app.installation.initialized_at".to_owned(),
            value: json!(now),
            created_at: now.into(),
            updated_at: None,
        },
        setting_model::<PasswordHashSetting>(6, PasswordHashSetting::default_value(), now),
        setting::Model {
            id: 7,
            oid: Uuid::new_v4(),
            key: "openid_connect.dynamic_registration.enabled".to_owned(),
            value: json!(false),
            created_at: now.into(),
            updated_at: None,
        },
        setting_model::<LoginDomainSetting>(11, Some("https://ui.example.com".to_owned()), now),
        setting::Model {
            id: 10,
            oid: Uuid::new_v4(),
            key: "openid_connect.device_authorization".to_owned(),
            value: json!(DeviceAuthorizationSettings::default()),
            created_at: now.into(),
            updated_at: None,
        },
    ]
}

fn setting_model<S>(id: i32, value: S::Value, now: DateTime<Utc>) -> setting::Model
where
    S: SettingDefinition,
{
    setting::Model {
        id,
        oid: Uuid::new_v4(),
        key: S::KEY.to_owned(),
        value: to_value(value).unwrap(),
        created_at: now.into(),
        updated_at: None,
    }
}

fn test_user(oid: Uuid, version: Uuid, now: DateTime<Utc>) -> user::Model {
    user::Model {
        id: 10,
        oid,
        version,
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
        preferences: json!({}),
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

fn test_metadata(client_id: i64, now: DateTime<Utc>) -> ClientOpenIdConnectModel {
    ClientOpenIdConnectModel {
        id: 8,
        client_id,
        post_logout_redirect_uris: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        response_types: None,
        grant_types: None,
        contacts: None,
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        sector_identifier_uri: None,
        subject_type: None,
        id_token_signed_response_algs: None,
        id_token_encrypted_response_algs: None,
        id_token_encrypted_response_encs: None,
        userinfo_signed_response_algs: None,
        userinfo_encrypted_response_algs: None,
        userinfo_encrypted_response_encs: None,
        request_object_signing_algs: None,
        request_object_encryption_algs: None,
        request_object_encryption_encs: None,
        token_endpoint_auth_methods: None,
        token_endpoint_auth_signing_algs: None,
        default_max_age: None,
        require_auth_time: None,
        default_acr_values: None,
        initiate_login_uri: None,
        request_uris: None,
        settings: json!({}),
        created_at: now.into(),
        updated_at: None,
    }
}

fn test_session(oid: Uuid, user_id: i64, now: DateTime<Utc>) -> SessionModel {
    SessionModel {
        id: 9,
        oid,
        user_id,
        status: "active".to_owned(),
        acr: None,
        acr_expires_at: None,
        amr: json!(["pwd"]),
        device_name: None,
        device_type: None,
        os_name: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
        user_agent: None,
        ip_address: None,
        country: None,
        city: None,
        last_active_at: now.into(),
        authenticated_at: None,
        expires_at: (now + Duration::days(7)).into(),
        revoked_at: None,
        created_at: now.into(),
        updated_at: None,
    }
}
