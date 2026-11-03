use crate::{
    openid_connect::tests::fixtures::scope_catalog::TestScopeCatalog, setting::SettingsSnapshot,
};

use super::*;
use identity_domain::{authorization::catalog::ManagementScope, openid_connect::ApiScope};

#[tokio::test]
async fn discovery_and_validation_use_catalog_instead_of_static_capabilities() {
    let settings = SettingsSnapshot::default().with_section(&AppSettings {
        console_domain: None,
        domain: Some("https://identity.example.com".to_owned()),
        ..Default::default()
    });
    let settings = settings.with_section(&InstallationSettings {
        initialized: true,
        initialized_at: None,
    });
    let provider = OpenIdProviderService::new(Arc::new(settings)).with_scope_catalog(Arc::new(
        TestScopeCatalog(vec!["openid".into(), "orders.read".into()]),
    ));
    assert_eq!(
        provider
            .discovery_metadata()
            .await
            .unwrap()
            .scopes_supported
            .unwrap(),
        ["openid", "orders.read"]
    );
    provider
        .validate_scope_names("openid orders.read orders.read")
        .await
        .unwrap();
    for scope in ["profile", "orders", "orders.write", "orders\tread"] {
        assert_eq!(
            provider
                .validate_scope_names(scope)
                .await
                .unwrap_err()
                .code(),
            10009
        );
    }
}

#[tokio::test]
async fn wildcard_requests_expand_known_names_at_any_depth_without_crossing_boundaries() {
    let provider = OpenIdProviderService::new(Arc::new(SettingsSnapshot::default()))
        .with_scope_catalog(Arc::new(TestScopeCatalog(vec![
            "openid".into(),
            "account.read".into(),
            "account.update".into(),
            "orders.read".into(),
            "orders.item.read".into(),
            "orders2.read".into(),
            "management.unknown".into(),
        ])));
    let scopes = provider
        .resolve_scope("openid account.* orders.*")
        .await
        .unwrap();
    assert!(!scopes.has_patterns());
    assert!(scopes.allows(ApiScope::AccountRead));
    assert!(scopes.allows(ApiScope::AccountUpdate));
    assert!(scopes.matches("orders.read"));
    assert!(scopes.matches("orders.item.read"));
    assert!(!scopes.matches("orders2.read"));
    assert_eq!(
        provider
            .resolve_scope("orders.item.*")
            .await
            .unwrap()
            .names(),
        ["orders.item.read"]
    );
    let management = provider.resolve_scope("management.*").await.unwrap();
    assert_eq!(
        management.management_scopes().len(),
        ManagementScope::ALL.len()
    );
    assert!(!management.has_patterns());
    assert!(!management.matches("management.unknown"));
    for invalid in [
        "missing.*",
        "management.unknown.*",
        "orders.*.read",
        "orders..*",
        "*",
    ] {
        assert!(provider.resolve_scope(invalid).await.is_err(), "{invalid}");
    }
}
