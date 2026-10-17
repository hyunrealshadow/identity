use crate::{
    openid_connect::tests::fixtures::scope_catalog::TestScopeCatalog, setting::SettingsSnapshot,
};

use super::*;

#[tokio::test]
async fn discovery_and_validation_use_catalog_instead_of_static_capabilities() {
    let settings = SettingsSnapshot::default().with_section(&AppSettings {
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
