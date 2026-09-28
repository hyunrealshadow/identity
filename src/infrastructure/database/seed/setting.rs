use async_trait::async_trait;
use sea_orm::DatabaseConnection;

use super::Seed;
use crate::{
    application::error::AppError,
    infrastructure::{
        database::repository::setting::insert_missing_settings, settings::setting_registry,
    },
};
use identity_application::setting::SettingRegistry;

/// Stores the default of every built-in setting that has no row yet.
pub struct SettingDefaultsSeed;

#[async_trait]
impl Seed for SettingDefaultsSeed {
    fn name(&self) -> &'static str {
        "setting_defaults"
    }

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        ensure_setting_defaults(db, &setting_registry()).await
    }
}

/// Inserts all defaults in one `INSERT ... ON CONFLICT (key) DO NOTHING`.
///
/// Instances starting together may all run this: the unique key lets exactly
/// one insert win per setting, and a value already stored — by an operator or
/// by installation on another instance — is never overwritten.
pub async fn ensure_setting_defaults(
    db: &DatabaseConnection,
    registry: &SettingRegistry,
) -> Result<(), AppError> {
    insert_missing_settings(db, registry.defaults()?).await
}

#[cfg(test)]
mod tests {
    use identity_application::setting::{
        DomainSetting, LoginDomainSetting, OpenIdConnectSettings, SettingRegistry,
    };
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::ensure_setting_defaults;

    #[tokio::test]
    async fn seeds_every_default_without_overwriting_stored_values() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();
        let registry = SettingRegistry::default()
            .register::<DomainSetting>()
            .register::<LoginDomainSetting>()
            .register_section::<OpenIdConnectSettings>();

        ensure_setting_defaults(&db, &registry).await.unwrap();

        let log = db.into_transaction_log();
        assert_eq!(log.len(), 1);
        let sql = format!("{:?}", log[0]);
        assert!(sql.contains(r#"INSERT INTO \"setting\""#), "{sql}");
        assert!(sql.contains(r#"ON CONFLICT (\"key\") DO NOTHING"#), "{sql}");
        assert!(sql.contains("app.domain"), "{sql}");
        assert!(sql.contains("app.login_domain"), "{sql}");
        assert!(
            sql.contains("openid_connect.dynamic_registration.enabled"),
            "{sql}"
        );
    }
}
