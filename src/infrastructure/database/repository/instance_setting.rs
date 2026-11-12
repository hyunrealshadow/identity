//! Transactional persistence for instance settings management.
//!
//! A write re-checks live management authority, serializes concurrent editors
//! with an advisory lock, compares the section version against the stored
//! values, writes the changes and appends the semantic audit record before
//! committing. An audit failure rolls the change back.

use std::collections::HashMap;

use async_trait::async_trait;
use identity_application::{
    rbac::RbacManagementRepositoryError,
    setting::{
        AppSettings, BreachedPasswordCheckEnabledSetting, InstallationSettings,
        OpenIdConnectSettings, PasswordHashSetting,
        management::{
            InstanceSettingRepository, InstanceSettingRepositoryError, InstanceSettingsState,
            UpdateInstanceSettingsTransaction,
        },
    },
};
use identity_domain::authorization::ManagementScope;
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, TransactionTrait};

use super::{
    rbac_management::{audit::append_semantic_audit, authority::recheck_authority},
    setting::write_settings,
};
use crate::{
    database::{entity::setting::Entity as SettingEntity, query::advisory_transaction_lock},
    settings::setting_registry,
};

/// Advisory lock serializing instance settings writes.
const INSTANCE_SETTINGS_LOCK: i64 = 7_311_927_402_118_505_231;

pub struct InstanceSettingRepositoryImpl {
    db: DatabaseConnection,
}

impl InstanceSettingRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn storage(
    error: impl std::error::Error + Send + Sync + 'static,
) -> InstanceSettingRepositoryError {
    InstanceSettingRepositoryError::Storage(Box::new(error))
}

fn from_management(error: RbacManagementRepositoryError) -> InstanceSettingRepositoryError {
    use InstanceSettingRepositoryError as Setting;
    use RbacManagementRepositoryError as Shared;
    match error {
        Shared::Authorization(source) => Setting::Authorization(source),
        Shared::AuditFailed(source) => Setting::AuditFailed(source),
        Shared::LastRecoverableAdministrator => Setting::LastRecoverableAdministrator,
        other => Setting::Storage(Box::new(other)),
    }
}

/// Every registered setting as stored, with declared defaults for missing rows.
async fn load_state<C: ConnectionTrait>(
    db: &C,
) -> Result<InstanceSettingsState, InstanceSettingRepositoryError> {
    let rows = SettingEntity::find().all(db).await.map_err(storage)?;
    let raw: HashMap<_, _> = rows.into_iter().map(|row| (row.key, row.value)).collect();
    let snapshot = setting_registry().resolve(&raw, None).map_err(storage)?;
    Ok(InstanceSettingsState {
        app: snapshot.section::<AppSettings>(),
        installation: snapshot.section::<InstallationSettings>(),
        openid_connect: snapshot.section::<OpenIdConnectSettings>(),
        password_hash: snapshot.get::<PasswordHashSetting>(),
        breached_password_check_enabled: snapshot.get::<BreachedPasswordCheckEnabledSetting>(),
    })
}

#[async_trait]
impl InstanceSettingRepository for InstanceSettingRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "load_instance_settings"))]
    async fn load(&self) -> Result<InstanceSettingsState, InstanceSettingRepositoryError> {
        load_state(&self.db).await
    }

    #[tracing::instrument(skip_all, name = "db.transaction", fields(db.system = "postgresql", db.operation = "update_instance_settings", setting.section = transaction.section.as_str()))]
    async fn update(
        &self,
        transaction: UpdateInstanceSettingsTransaction,
    ) -> Result<InstanceSettingsState, InstanceSettingRepositoryError> {
        let UpdateInstanceSettingsTransaction {
            authority,
            section,
            expected_version,
            build,
        } = transaction;
        let txn = self.db.begin().await.map_err(storage)?;
        recheck_authority(&txn, &authority, ManagementScope::SettingsWrite, None)
            .await
            .map_err(from_management)?;
        txn.execute(&advisory_transaction_lock(INSTANCE_SETTINGS_LOCK))
            .await
            .map_err(storage)?;

        let current = load_state(&txn).await?;
        let current_version = section.version(&current);
        if current_version != expected_version {
            return Err(InstanceSettingRepositoryError::VersionConflict { current_version });
        }
        let changes = build(&current).map_err(InstanceSettingRepositoryError::Invalid)?;
        write_settings(&txn, changes).await.map_err(storage)?;
        let next = load_state(&txn).await?;

        append_semantic_audit(
            &txn,
            &authority,
            section.audit_action(),
            "setting",
            section.audit_target_oid(),
            "",
        )
        .await
        .map_err(from_management)?;
        txn.commit().await.map_err(storage)?;
        Ok(next)
    }
}
