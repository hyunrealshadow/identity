use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use identity_domain::{
    auth::SessionOid,
    openid_connect::{ScopeSet, resource::OAuthResource},
};

use crate::openid_connect::tests::fixtures::scope_catalog::TestScopeCatalog;

use crate::openid_connect::token::tests::{fixtures::*, *};

const ORDERS: &str = "urn:orders";
const ORDERS_ALT: &str = "urn:orders-alt";
const BILLING: &str = "urn:billing";
const DISABLED: &str = "urn:disabled";

fn provider_with_business_catalog() -> Arc<OpenIdProviderService> {
    let orders = business_resource(ORDERS, &["orders.read", "orders.write"]);
    let billing = business_resource(BILLING, &["billing.read"]);
    let rbac = TestRbacRepository::shared(vec![
        delegated_user_state(&orders, UserOid(Uuid::new_v4())),
        delegated_user_state(&billing, UserOid(Uuid::new_v4())),
    ]);
    Arc::new(
        Arc::try_unwrap(provider_service())
            .ok()
            .unwrap()
            .with_scope_catalog(Arc::new(TestScopeCatalog(vec![
                "openid".into(),
                "offline_access".into(),
                "orders.read".into(),
                "orders.write".into(),
                "billing.read".into(),
            ])))
            .with_resource_repo(Arc::new(TestOAuthResources::new(vec![
                oauth_resource(ORDERS, &["orders.read", "orders.write"]),
                oauth_resource(ORDERS_ALT, &["orders.read"]),
                oauth_resource(BILLING, &["billing.read"]),
                OAuthResource {
                    uri: DISABLED.into(),
                    scopes: vec!["orders.read".into()],
                    enabled: false,
                },
            ])))
            .with_rbac_authorization_repository(rbac),
    )
}

#[tokio::test]
async fn resource_validation_rejects_invalid_targets_and_deduplicates_exact_uris() {
    let provider = provider_with_business_catalog();
    for uri in [
        "relative",
        "https://api.example.com/orders#fragment",
        DISABLED,
        "urn:unknown",
        "URN:ORDERS",
        "https://api.example.com/%ZZ",
    ] {
        let error = provider
            .select_resources(&[uri.to_owned()], &[], "openid orders.read offline_access")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), 10006, "{uri}");
    }

    let selected = provider
        .select_resources(
            &[ORDERS.to_owned(), ORDERS.to_owned()],
            &[],
            "openid offline_access orders.read orders.write",
        )
        .await
        .unwrap();
    assert_eq!(selected.resources, [ORDERS]);
    assert_eq!(
        selected.scope,
        "openid offline_access orders.read orders.write"
    );

    // Wildcards are selectors expanded against the target resource's own
    // concrete scope rows, never persisted permissions.
    let expanded = provider
        .select_resources(&[ORDERS.to_owned()], &[], "openid orders.* offline_access")
        .await
        .unwrap();
    assert_eq!(
        expanded.scope,
        "openid offline_access orders.read orders.write"
    );

    // A custom API scope needs an explicit owning resource.
    assert_eq!(
        provider
            .select_resources(&[], &[], "orders.read")
            .await
            .err()
            .unwrap()
            .code(),
        10006
    );

    // A same-code scope from another resource never authorizes the target.
    assert_eq!(
        provider
            .select_resources(
                &[BILLING.to_owned()],
                &[],
                "openid orders.read offline_access",
            )
            .await
            .err()
            .unwrap()
            .code(),
        10006
    );

    let scope = ScopeSet::parse("openid orders.read offline_access").unwrap();
    assert_eq!(
        provider
            .validate_authorization_resources(&[ORDERS.to_owned()], &scope)
            .await
            .unwrap(),
        [ORDERS]
    );
    assert_eq!(
        provider
            .validate_authorization_resources(&[BILLING.to_owned()], &scope)
            .await
            .unwrap_err()
            .code(),
        10006
    );

    // A flat token cannot represent two business audiences, even when they
    // happen to use the same code. Fail closed instead of smuggling it.
    assert_eq!(
        provider
            .validate_authorization_resources(&[ORDERS.to_owned(), ORDERS_ALT.to_owned()], &scope,)
            .await
            .unwrap_err()
            .code(),
        10006
    );
    assert_eq!(
        provider
            .select_resources(
                &[ORDERS.to_owned(), ORDERS_ALT.to_owned()],
                &[],
                "openid orders.read offline_access",
            )
            .await
            .unwrap_err()
            .code(),
        10006
    );
}

#[tokio::test]
async fn resource_selection_preserves_the_full_refresh_grant_and_rejects_expansion_before_consumption()
 {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let key = key_for_algorithm("RS256");
    let public = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.clone(),
        _ => unreachable!(),
    };
    let mut service = build_token_service_with_key(repo.clone(), key, user_oid);
    let resource = business_resource(ORDERS, &["orders.read", "orders.write"]);
    let user_state = delegated_user_state(&resource, UserOid(user_oid));
    let rbac = TestRbacRepository::shared(vec![user_state.clone()]);
    let provider = Arc::try_unwrap(provider_service())
        .ok()
        .unwrap()
        .with_scope_catalog(Arc::new(TestScopeCatalog(vec![
            "openid".into(),
            "offline_access".into(),
            "orders.read".into(),
            "orders.write".into(),
        ])))
        .with_resource_repo(Arc::new(
            TestOAuthResources::new(vec![oauth_resource(
                ORDERS,
                &["orders.read", "orders.write"],
            )])
            .with_client_ceiling(
                Uuid::nil(),
                ORDERS,
                &["openid", "offline_access", "orders.read", "orders.write"],
            ),
        ))
        .with_rbac_authorization_repository(rbac.clone());
    service.provider_service = Arc::new(provider);
    service = service.with_rbac_authorization_repository(rbac);
    service.client_repo = Arc::new(AssignedScopesClientRepository {
        scopes: vec![
            "openid".into(),
            "offline_access".into(),
            "orders.read".into(),
            "orders.write".into(),
        ],
    });

    let verifier = "verifier-resource-selection";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: vec![ORDERS.to_owned()],
                scope: "openid offline_access orders.read orders.write".to_owned(),
                nonce: None,
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".parse().unwrap()),
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                auth_time: None,
                acr: None,
                amr: vec![],
                claims: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                redirect_uri_was_supplied: true,
                management: Some(delegated_snapshot(&user_state)),
            }),
            Utc::now() + Duration::minutes(10),
        )
        .await
        .unwrap();
    let mut params = AuthorizationCodeGrantParams {
        resources: vec![BILLING.to_owned()],
        code: STANDARD.encode(record.oid.as_bytes()),
        redirect_uri: Some("https://client.example.com/callback".to_owned()),
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
        code_verifier: Some(verifier.into()),
    };
    assert_eq!(
        service
            .exchange_authorization_code(params.clone())
            .await
            .unwrap_err()
            .code(),
        10006
    );
    assert!(
        repo.find_by_oid(record.oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );

    params.resources = vec![ORDERS.to_owned()];
    let initial = service.exchange_authorization_code(params).await.unwrap();
    assert_eq!(
        initial.scope,
        "openid offline_access orders.read orders.write"
    );
    let verifier = RS256.verifier_from_pem(public.as_bytes()).unwrap();
    let (access, _) = jwt::decode_with_verifier(&initial.access_token, &verifier).unwrap();
    assert_eq!(access.audience().unwrap(), [ORDERS]);
    let (id, _) = jwt::decode_with_verifier(initial.id_token.as_ref().unwrap(), &verifier).unwrap();
    assert_eq!(id.audience().unwrap(), [Uuid::nil().to_string().as_str()]);
    let refresh_token = initial.refresh_token.unwrap();
    let refresh_oid = Uuid::from_slice(&STANDARD.decode(&refresh_token).unwrap()).unwrap();
    let stored = repo.find_by_oid(refresh_oid).await.unwrap().unwrap();
    let ClientAuthorizationData::RefreshToken(data) = stored.data else {
        panic!("refresh data")
    };
    assert_eq!(data.resources, [ORDERS]);
    assert_eq!(data.scope, "openid offline_access orders.read orders.write");

    let mut refresh = RefreshTokenGrantParams {
        resources: vec![BILLING.to_owned()],
        refresh_token,
        scope: None,
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    };
    assert_eq!(
        service
            .exchange_refresh_token(refresh.clone())
            .await
            .unwrap_err()
            .code(),
        10006
    );
    assert!(
        repo.find_by_oid(refresh_oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );

    // The refreshed access token keeps the full stored grant for the single
    // business audience; the original grant is not narrowed by the exchange.
    refresh.resources = vec![ORDERS.to_owned()];
    let refreshed = service.exchange_refresh_token(refresh).await.unwrap();
    assert_eq!(
        refreshed.scope,
        "openid offline_access orders.read orders.write"
    );
    let (access, _) = jwt::decode_with_verifier(&refreshed.access_token, &verifier).unwrap();
    assert_eq!(access.audience().unwrap(), [ORDERS]);
    let next_oid =
        Uuid::from_slice(&STANDARD.decode(refreshed.refresh_token.unwrap()).unwrap()).unwrap();
    let next = repo.find_by_oid(next_oid).await.unwrap().unwrap();
    let ClientAuthorizationData::RefreshToken(next) = next.data else {
        panic!("refresh data")
    };
    assert_eq!(next.resources, [ORDERS]);
    assert_eq!(next.scope, "openid offline_access orders.read orders.write");

    let restored = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: Vec::new(),
            refresh_token: STANDARD.encode(next_oid.as_bytes()),
            scope: None,
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap();
    assert_eq!(
        restored.scope,
        "openid offline_access orders.read orders.write"
    );
}
