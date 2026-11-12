//! Client management writes against PostgreSQL: live authority recheck,
//! optimistic locking, built-in protection, permanent withdrawal and audit.

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use identity_application::{
    client::{
        AddClientCredentialTransaction, ClientManagementRepository,
        ClientManagementRepositoryError, ClientPlatform, ClientProtocolSettings,
        ClientStateTransaction, CreateClientSecretTransaction, CreateClientTransaction,
        NewClientSecret, RevokeClientCredentialTransaction, UpdateClientTransaction,
    },
    rbac::{
        ClientScopeAssignment, RbacManagementAuthority, RbacManagementRepository,
        RbacManagementRepositoryError, ScopeOid, SetClientScopesTransaction,
    },
};
use identity_domain::{
    authorization::{
        ActorContext, HumanAuthenticationContext, ManagementAuthorityRepository,
        ManagementAuthorizationSnapshot, ManagementScope, RequestId,
    },
    openid_connect::{
        GrantType, OpenIdConnectClientPlatformType, OpenIdConnectClientRepository,
        OpenIdConnectCredentialData, OpenIdConnectCredentialOid, TokenEndpointAuthMethod,
        resource::OAuthResourceRepository,
    },
    user::UserOid,
};
use identity_infrastructure::database::{
    repository::{
        authorization::AuthorizationRepositoryImpl,
        client_management::ClientManagementRepositoryImpl,
        oauth_resource::OAuthResourceRepositoryImpl,
        openid_connect::OpenIdConnectClientRepositoryImpl,
        rbac_management::RbacManagementRepositoryImpl,
    },
    seed,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

use super::common::isolated;

async fn sql(db: &DatabaseConnection, statement: &str) {
    db.execute_unprepared(statement).await.unwrap();
}

async fn scalar<T: sea_orm::TryGetable>(db: &DatabaseConnection, statement: &str) -> T {
    db.query_one_raw(Statement::from_string(
        DbBackend::Postgres,
        statement.to_owned(),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "value")
    .unwrap()
}

/// A recoverable administrator must exist for any audited management write.
pub(super) async fn owner(db: &DatabaseConnection) {
    sql(db, r#"
        INSERT INTO "user"(oid,name,name_normalized,email,email_normalized,email_verified)
            VALUES(gen_random_uuid(),'owner','owner','owner@example.test','owner@example.test',true);
        INSERT INTO user_credential(oid,user_id,type,data)
            SELECT gen_random_uuid(),id,'password','{}'::jsonb FROM "user" WHERE name='owner';
        INSERT INTO user_role(oid,user_id,role_id,reason)
            SELECT gen_random_uuid(),u.id,r.id,'' FROM "user" u,
              (SELECT role_id AS id FROM role_permission GROUP BY role_id ORDER BY count(*) DESC LIMIT 1) r
            WHERE u.name='owner';
    "#).await;
}

/// A machine principal granted the given management scopes for itself.
pub(super) async fn machine(
    db: &DatabaseConnection,
    scopes: &[ManagementScope],
) -> RbacManagementAuthority {
    let oid = Uuid::new_v4();
    let codes = scopes
        .iter()
        .map(|scope| format!("'{}'", scope.name()))
        .collect::<Vec<_>>()
        .join(",");
    sql(db, &format!(r#"
        INSERT INTO client(oid,name,protocol) VALUES('{oid}','machine-admin','openid_connect');
        INSERT INTO client_openid_connect(client_id,grant_types,token_endpoint_auth_methods)
            SELECT id,'["client_credentials"]','["client_secret_basic"]' FROM client WHERE oid='{oid}';
        INSERT INTO client_scope(client_id,scope_id,client_granted)
            SELECT c.id,s.id,true FROM client c, scope s
            WHERE c.oid='{oid}' AND s.built_in AND s.code IN ({codes});
    "#)).await;
    let boundary = OAuthResourceRepositoryImpl::new(db.clone())
        .client_authority_fingerprint(oid)
        .await
        .unwrap()
        .unwrap();
    RbacManagementAuthority::new(
        ActorContext::for_client(oid, RequestId::new("client-management-test").unwrap(), None),
        scopes.iter().copied().collect::<BTreeSet<_>>(),
        None,
        oid,
        boundary,
    )
}

fn web_settings(redirect: &str) -> ClientProtocolSettings {
    ClientProtocolSettings {
        platforms: vec![ClientPlatform {
            platform: OpenIdConnectClientPlatformType::Web,
            redirect_uris: vec![redirect.to_owned()],
        }],
        post_logout_redirect_uris: vec!["https://app.example.test/signed-out".to_owned()],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        // Derived from credentials by the repository; ignored on write.
        token_endpoint_auth_methods: Vec::new(),
        allow_public_client_flow: false,
        require_pushed_authorization_requests: false,
        skip_consent: false,
        cors_enabled: true,
        oauth_version: None,
        include_scoped_claims_in_id_token: false,
        include_scoped_claims_in_access_token: false,
    }
}

/// Insert one live issued artifact and return its OID.
async fn issued_artifact(db: &DatabaseConnection, client: Uuid) -> Uuid {
    let oid = Uuid::new_v4();
    sql(db, &format!(
        "INSERT INTO client_authorization(oid,client_id,type,data,expires_at)
         SELECT '{oid}',id,'access_token','{{}}'::jsonb,now()+interval '1 hour' FROM client WHERE oid='{client}'"
    )).await;
    oid
}

async fn withdrawn(db: &DatabaseConnection, artifact: Uuid) -> bool {
    scalar::<bool>(
        db,
        &format!(
            "SELECT (revoked_at IS NOT NULL AND data->>'_authority_withdrawn' = 'true') AS value
         FROM client_authorization WHERE oid='{artifact}'"
        ),
    )
    .await
}

async fn audit_count(db: &DatabaseConnection, action: &str, target: Uuid) -> i64 {
    scalar::<i64>(db, &format!(
        "SELECT count(*)::bigint AS value FROM security_audit WHERE action='{action}' AND target_oid='{target}'"
    )).await
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_client_management_rechecks_authority_and_withdraws_on_boundary_changes() {
    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        owner(&db).await;
        let authority = machine(&db, &[
            ManagementScope::ClientsCreate,
            ManagementScope::ClientsUpdate,
            ManagementScope::ClientsState,
            ManagementScope::ClientsDelete,
            ManagementScope::ClientCredentialsCreate,
        ]).await;
        let repo = ClientManagementRepositoryImpl::new(db.clone());
        let protocol = OpenIdConnectClientRepositoryImpl::new(db.clone());

        // Create: protocol rows, derived CORS origin and audit in one change.
        let created = repo.create_client(CreateClientTransaction {
            client_oid: Uuid::new_v4(),
            name: "Orders".to_owned(),
            description: String::new(),
            names: Vec::new(),
            descriptions: Vec::new(),
            settings: web_settings("https://app.example.test/callback"),
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap();
        assert!(created.enabled && !created.built_in);
        assert_eq!(created.settings.platforms[0].redirect_uris, ["https://app.example.test/callback"]);
        assert_eq!(created.cors_origins, ["https://app.example.test"]);
        assert_eq!(audit_count(&db, "client.create", created.oid).await, 1);
        assert!(protocol.find_by_oid(created.oid).await.unwrap().is_some());

        // A display edit keeps issued artifacts; a redirect change withdraws them.
        let artifact = issued_artifact(&db, created.oid).await;
        let renamed = repo.update_client(UpdateClientTransaction {
            client_oid: created.oid,
            expected_version: created.version,
            name: Some("Orders portal".to_owned()),
            description: None, names: None, descriptions: None, settings: None,
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap();
        assert_ne!(renamed.version, created.version);
        assert!(!withdrawn(&db, artifact).await);

        let stale = repo.update_client(UpdateClientTransaction {
            client_oid: created.oid,
            expected_version: created.version,
            name: Some("Lost update".to_owned()),
            description: None, names: None, descriptions: None, settings: None,
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap_err();
        assert!(matches!(stale, ClientManagementRepositoryError::VersionConflict { current_version } if current_version == renamed.version));

        let moved = repo.update_client(UpdateClientTransaction {
            client_oid: created.oid,
            expected_version: renamed.version,
            name: None, description: None, names: None, descriptions: None,
            settings: Some(web_settings("https://portal.example.test/callback")),
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap();
        assert!(withdrawn(&db, artifact).await);
        assert_eq!(moved.cors_origins, ["https://portal.example.test"]);

        // Disabling hides the client from every protocol lookup and withdraws;
        // enabling again never revives what was withdrawn.
        let later = issued_artifact(&db, created.oid).await;
        let disabled = repo.set_client_enabled(ClientStateTransaction {
            client_oid: created.oid,
            expected_version: moved.version,
            reason: String::new(),
            authority: authority.clone(),
        }, false).await.unwrap();
        assert!(!disabled.enabled);
        assert!(protocol.find_by_oid(created.oid).await.unwrap().is_none());
        assert!(withdrawn(&db, later).await);
        let enabled = repo.set_client_enabled(ClientStateTransaction {
            client_oid: created.oid,
            expected_version: disabled.version,
            reason: String::new(),
            authority: authority.clone(),
        }, true).await.unwrap();
        assert!(enabled.enabled);
        assert!(protocol.find_by_oid(created.oid).await.unwrap().is_some());
        assert!(withdrawn(&db, later).await);

        // Human-only operations reject a machine principal even when the
        // scope row exists, and change nothing.
        let denied = repo.delete_client(ClientStateTransaction {
            client_oid: created.oid,
            expected_version: enabled.version,
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap_err();
        assert!(matches!(denied, ClientManagementRepositoryError::Authorization(_)), "{denied:?}");
        let denied = repo.create_client_secret(CreateClientSecretTransaction {
            client_oid: created.oid,
            expected_version: enabled.version,
            replaces: None,
            secret: NewClientSecret {
                credential_oid: Uuid::new_v4(),
                data: OpenIdConnectCredentialData::ClientSecret { secret: "unused-secret".to_owned() },
                plaintext: "unused-secret".to_owned(),
                lifetime_days: 30,
            },
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap_err();
        assert!(matches!(denied, ClientManagementRepositoryError::Authorization(_)), "{denied:?}");
        assert_eq!(repo.find_client(created.oid).await.unwrap().unwrap().version, enabled.version);
        assert!(repo.list_client_credentials(created.oid).await.unwrap().is_empty());

        // Built-in clients are protected from every write.
        sql(&db, &format!("UPDATE client SET built_in=true WHERE oid='{}'", created.oid)).await;
        let protected = repo.set_client_enabled(ClientStateTransaction {
            client_oid: created.oid,
            expected_version: enabled.version,
            reason: String::new(),
            authority: authority.clone(),
        }, false).await.unwrap_err();
        assert!(matches!(protected, ClientManagementRepositoryError::BuiltInProtected));

        // Losing the granted scope fails the live recheck despite the token scopes.
        sql(&db, &format!(
            "UPDATE client_scope SET client_granted=false WHERE client_id=(SELECT id FROM client WHERE oid='{}')",
            authority.client_oid
        )).await;
        let revoked = repo.create_client(CreateClientTransaction {
            client_oid: Uuid::new_v4(),
            name: "Rejected".to_owned(),
            description: String::new(),
            names: Vec::new(),
            descriptions: Vec::new(),
            settings: web_settings("https://other.example.test/callback"),
            reason: String::new(),
            authority,
        }).await.unwrap_err();
        assert!(matches!(revoked, ClientManagementRepositoryError::Authorization(_)), "{revoked:?}");
        let missing = repo.find_client(Uuid::new_v4()).await.unwrap();
        assert!(missing.is_none());
    }).await;
}

async fn assigned_codes(db: &DatabaseConnection, client: Uuid) -> Vec<String> {
    db.query_all_raw(Statement::from_string(
        DbBackend::Postgres,
        format!(
            "SELECT s.code FROM client_scope cs JOIN scope s ON s.id=cs.scope_id
             JOIN client c ON c.id=cs.client_id WHERE c.oid='{client}' ORDER BY s.code"
        ),
    ))
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.try_get::<String>("", "code").unwrap())
    .collect()
}

async fn scope_oid(db: &DatabaseConnection, code: &str) -> ScopeOid {
    ScopeOid(
        scalar::<Uuid>(
            db,
            &format!("SELECT oid AS value FROM scope WHERE code='{code}'"),
        )
        .await,
    )
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_client_protocol_scopes_default_on_create_and_replace_with_the_full_set() {
    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        owner(&db).await;
        let authority = machine(&db, &[ManagementScope::ClientsCreate, ManagementScope::ClientsScopes]).await;
        let clients = ClientManagementRepositoryImpl::new(db.clone());
        let rbac = RbacManagementRepositoryImpl::new(db.clone());

        // An interactive client can sign users in from the start; a machine
        // client starts with no protocol scopes.
        let web = clients.create_client(CreateClientTransaction {
            client_oid: Uuid::new_v4(),
            name: "Portal".to_owned(),
            description: String::new(), names: Vec::new(), descriptions: Vec::new(),
            settings: web_settings("https://portal.example.test/callback"),
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap();
        assert_eq!(assigned_codes(&db, web.oid).await, ["email", "offline_access", "openid", "profile"]);
        let worker = clients.create_client(CreateClientTransaction {
            client_oid: Uuid::new_v4(),
            name: "Worker".to_owned(),
            description: String::new(), names: Vec::new(), descriptions: Vec::new(),
            settings: ClientProtocolSettings {
                platforms: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::ClientCredentials],
                cors_enabled: false,
                ..web_settings("https://unused.example.test/callback")
            },
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap();
        assert!(assigned_codes(&db, worker.oid).await.is_empty());

        // The submitted list replaces protocol scopes as well.
        let artifact = issued_artifact(&db, web.oid).await;
        let openid = scope_oid(&db, "openid").await;
        let replaced = rbac.set_client_scopes(SetClientScopesTransaction {
            client_oid: web.oid,
            scopes: vec![ClientScopeAssignment { scope_oid: openid, client_granted: false }],
            expected_version: web.version,
            reason: String::new(),
            authority: authority.clone(),
        }).await.unwrap();
        assert_eq!(assigned_codes(&db, web.oid).await, ["openid"]);
        assert!(withdrawn(&db, artifact).await);
        assert_eq!(audit_count(&db, "client.scopes.set", web.oid).await, 1);

        // A protocol scope is never held by the client itself; the rejected
        // change leaves the assignment and version untouched.
        let rejected = rbac.set_client_scopes(SetClientScopesTransaction {
            client_oid: web.oid,
            scopes: vec![ClientScopeAssignment { scope_oid: openid, client_granted: true }],
            expected_version: replaced.version,
            reason: String::new(),
            authority,
        }).await.unwrap_err();
        assert!(matches!(rejected, RbacManagementRepositoryError::ClientGrantNotAllowed { ref scope } if scope == "openid"), "{rejected:?}");
        assert_eq!(assigned_codes(&db, web.oid).await, ["openid"]);
        assert_eq!(clients.find_client(web.oid).await.unwrap().unwrap().version, replaced.version);
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_seed_removes_retired_management_scopes_and_their_relations() {
    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        // A database seeded before the retirement still holds the definition,
        // a custom role permission and a client assignment for it.
        sql(&db, r#"
            INSERT INTO scope(oid,resource_id,code,name,names,description,descriptions,built_in,enabled,version)
                SELECT gen_random_uuid(),resource_id,'management.administrator.read','Read administrators','{}'::jsonb,'','{}'::jsonb,true,true,gen_random_uuid()
                FROM scope WHERE code='management.user.read';
            INSERT INTO "role"(oid,name,names,description,descriptions,built_in,enabled,version)
                VALUES(gen_random_uuid(),'Auditors','{}'::jsonb,'','{}'::jsonb,false,true,gen_random_uuid());
            INSERT INTO role_permission(oid,role_id,scope_id)
                SELECT gen_random_uuid(),r.id,s.id FROM "role" r, scope s
                WHERE r.name='Auditors' AND s.code='management.administrator.read';
            INSERT INTO client(oid,name,protocol) VALUES(gen_random_uuid(),'legacy','openid_connect');
            INSERT INTO client_scope(client_id,scope_id,client_granted)
                SELECT c.id,s.id,false FROM client c, scope s
                WHERE c.name='legacy' AND s.code='management.administrator.read';
        "#).await;
        let before = scalar::<Uuid>(&db, "SELECT version AS value FROM \"role\" WHERE name='Auditors'").await;

        seed::run_all(&db).await.unwrap();

        assert_eq!(scalar::<i64>(&db, "SELECT count(*)::bigint AS value FROM scope WHERE code='management.administrator.read'").await, 0);
        assert_eq!(scalar::<i64>(&db, "SELECT count(*)::bigint AS value FROM role_permission rp JOIN \"role\" r ON r.id=rp.role_id WHERE r.name='Auditors'").await, 0);
        assert_eq!(scalar::<i64>(&db, "SELECT count(*)::bigint AS value FROM client_scope cs JOIN client c ON c.id=cs.client_id WHERE c.name='legacy'").await, 0);
        assert_ne!(scalar::<Uuid>(&db, "SELECT version AS value FROM \"role\" WHERE name='Auditors'").await, before);
        // Running the seed again is a no-op.
        seed::run_all(&db).await.unwrap();
    }).await;
}

/// The recoverable owner acting through an issuing client with a fresh AAL2
/// sign-in, which credential writes require.
pub(super) async fn administrator(
    db: &DatabaseConnection,
    scopes: &[ManagementScope],
) -> RbacManagementAuthority {
    let machine = machine(db, scopes).await;
    let user =
        UserOid(scalar::<Uuid>(db, r#"SELECT oid AS value FROM "user" WHERE name='owner'"#).await);
    let authorization = AuthorizationRepositoryImpl::new(db.clone());
    let current = authorization
        .find_user_permission_authority(user)
        .await
        .unwrap()
        .expect("owner has management permissions");
    let policy = authorization.current_policy_version().await.unwrap();
    RbacManagementAuthority::new(
        ActorContext::for_user(
            user,
            HumanAuthenticationContext::aal2(Some(Utc::now())),
            RequestId::new("client-credential-test").unwrap(),
            None,
        ),
        scopes.iter().copied().collect::<BTreeSet<_>>(),
        Some(ManagementAuthorizationSnapshot::for_user_permissions(
            &current, policy,
        )),
        machine.client_oid,
        machine.client_policy_version,
    )
}

fn new_secret() -> NewClientSecret {
    let secret = format!("secret-{}", Uuid::new_v4());
    NewClientSecret {
        credential_oid: Uuid::new_v4(),
        data: OpenIdConnectCredentialData::ClientSecret {
            secret: secret.clone(),
        },
        plaintext: secret,
        lifetime_days: 30,
    }
}

fn public_key() -> OpenIdConnectCredentialData {
    OpenIdConnectCredentialData::ClientPublicKey {
        public_key: "-----BEGIN PUBLIC KEY-----\nunused\n-----END PUBLIC KEY-----".to_owned(),
        jwk: None,
    }
}

fn jwks_uri() -> OpenIdConnectCredentialData {
    OpenIdConnectCredentialData::ClientJsonWebKeySet {
        jwks_uri: "https://client.example.test/jwks.json".parse().unwrap(),
        last_updated: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        public_keys: Vec::new(),
        jwks: Vec::new(),
    }
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_client_auth_methods_follow_credentials_within_their_limits() {
    use TokenEndpointAuthMethod::{
        ClientSecretBasic, ClientSecretPost, None as NoAuth, PrivateKeyJwt,
    };

    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        owner(&db).await;
        let authority = administrator(
            &db,
            &[
                ManagementScope::ClientsCreate,
                ManagementScope::ClientsUpdate,
                ManagementScope::ClientCredentialsCreate,
                ManagementScope::ClientCredentialsRotate,
                ManagementScope::ClientCredentialsRevoke,
            ],
        )
        .await;
        let repo = ClientManagementRepositoryImpl::new(db.clone());
        let methods = |oid: Uuid| {
            let repo = &repo;
            async move {
                repo.find_client(oid)
                    .await
                    .unwrap()
                    .unwrap()
                    .settings
                    .token_endpoint_auth_methods
            }
        };

        // Submitted methods are ignored: a new client without credentials and
        // without the public flow cannot authenticate at all.
        let mut settings = web_settings("https://app.example.test/callback");
        settings.token_endpoint_auth_methods = vec![ClientSecretBasic, PrivateKeyJwt];
        let client = repo
            .create_client(CreateClientTransaction {
                client_oid: Uuid::new_v4(),
                name: "Payments".to_owned(),
                description: String::new(),
                names: Vec::new(),
                descriptions: Vec::new(),
                settings,
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert!(client.settings.token_endpoint_auth_methods.is_empty());
        let oid = client.oid;
        let mut version = client.version;

        // Each issued secret keeps HTTP Basic and the request body; five is the limit.
        let mut secrets = Vec::new();
        for _ in 0..5 {
            let issued = repo
                .create_client_secret(CreateClientSecretTransaction {
                    client_oid: oid,
                    expected_version: version,
                    replaces: None,
                    secret: new_secret(),
                    reason: String::new(),
                    authority: authority.clone(),
                })
                .await
                .unwrap();
            version = issued.client.version;
            secrets.push(issued.secret.credential.oid);
        }
        assert_eq!(methods(oid).await, [ClientSecretBasic, ClientSecretPost]);
        let sixth = repo
            .create_client_secret(CreateClientSecretTransaction {
                client_oid: oid,
                expected_version: version,
                replaces: None,
                secret: new_secret(),
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                sixth,
                ClientManagementRepositoryError::CredentialLimitReached { max: 5 }
            ),
            "{sixth:?}"
        );
        assert_eq!(repo.list_client_credentials(oid).await.unwrap().len(), 5);

        // Rotation at the limit revokes first, so it still succeeds.
        let rotated = repo
            .create_client_secret(CreateClientSecretTransaction {
                client_oid: oid,
                expected_version: version,
                replaces: Some(secrets[0]),
                secret: new_secret(),
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        version = rotated.client.version;

        // A public key adds private_key_jwt; only one JWKS URI may be usable.
        let add = |data: OpenIdConnectCredentialData, version: Uuid, action: &'static str| {
            AddClientCredentialTransaction {
                client_oid: oid,
                expected_version: version,
                credential_oid: Uuid::new_v4(),
                data,
                hint: None,
                expires_at: Some(Utc::now() + Duration::days(30)),
                action,
                reason: String::new(),
                authority: authority.clone(),
            }
        };
        let key = repo
            .add_client_credential(add(public_key(), version, "client.public_key.create"))
            .await
            .unwrap();
        version = key.client.version;
        assert_eq!(
            key.client.settings.token_endpoint_auth_methods,
            [ClientSecretBasic, ClientSecretPost, PrivateKeyJwt]
        );
        assert_eq!(audit_count(&db, "client.public_key.create", oid).await, 1);

        let mut jwks = add(jwks_uri(), version, "client.jwks_uri.create");
        jwks.expires_at = None;
        let first = repo.add_client_credential(jwks.clone()).await.unwrap();
        version = first.client.version;
        assert!(first.credential.expires_at.is_none());
        jwks.expected_version = version;
        jwks.credential_oid = Uuid::new_v4();
        let second = repo.add_client_credential(jwks).await.unwrap_err();
        assert!(
            matches!(
                second,
                ClientManagementRepositoryError::CredentialLimitReached { max: 1 }
            ),
            "{second:?}"
        );
        assert_eq!(
            repo.find_client(oid).await.unwrap().unwrap().version,
            version
        );

        // Revoking every key credential removes private_key_jwt; revoked
        // credentials drop out of the listing.
        let revoke = |credential_oid: OpenIdConnectCredentialOid, version: Uuid| {
            RevokeClientCredentialTransaction {
                client_oid: oid,
                credential_oid,
                expected_version: version,
                reason: String::new(),
                authority: authority.clone(),
            }
        };
        let revoked = repo
            .revoke_client_credential(revoke(key.credential.oid, version))
            .await
            .unwrap();
        version = revoked.client.version;
        assert_eq!(
            methods(oid).await,
            [ClientSecretBasic, ClientSecretPost, PrivateKeyJwt]
        );
        let revoked = repo
            .revoke_client_credential(revoke(first.credential.oid, version))
            .await
            .unwrap();
        version = revoked.client.version;
        assert_eq!(methods(oid).await, [ClientSecretBasic, ClientSecretPost]);
        let listed = repo.list_client_credentials(oid).await.unwrap();
        assert_eq!(listed.len(), 5);
        assert!(
            listed
                .iter()
                .all(|credential| credential.revoked_at.is_none())
        );

        // The public flow switch alone adds or removes `none`.
        let mut public = web_settings("https://app.example.test/callback");
        public.allow_public_client_flow = true;
        let updated = repo
            .update_client(UpdateClientTransaction {
                client_oid: oid,
                expected_version: version,
                name: None,
                description: None,
                names: None,
                descriptions: None,
                settings: Some(public),
                reason: String::new(),
                authority: authority.clone(),
            })
            .await
            .unwrap();
        assert_eq!(
            updated.settings.token_endpoint_auth_methods,
            [ClientSecretBasic, ClientSecretPost, NoAuth]
        );
    })
    .await;
}
