use identity_domain::setting::repository::{SettingRepository, SettingRepositoryError};
use identity_domain::setting::{SettingDefinition, SettingEntry};

mockall::mock! {
    pub SettingRepository {}

    #[async_trait::async_trait]
    impl SettingRepository for SettingRepository {
        async fn get<S>(&self)
            -> Result<Option<SettingEntry<S::Value>>, SettingRepositoryError>
        where
            S: SettingDefinition + 'static;
        async fn upsert<S>(&self, value: &S::Value)
            -> Result<SettingEntry<S::Value>, SettingRepositoryError>
        where
            S: SettingDefinition + 'static;
    }
}
