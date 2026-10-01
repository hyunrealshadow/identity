#[derive(Debug, Clone)]
pub struct ScopeDescription {
    pub name: String,
    pub display_name: String,
    pub description: String,
    /// BCP 47 language tag to consent description.
    pub descriptions: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
#[error("failed to load scope descriptions: {0}")]
pub struct ScopeCatalogError(pub String);

#[async_trait::async_trait]
pub trait ScopeCatalogRepository: Send + Sync {
    async fn find_by_names(
        &self,
        names: &[&str],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError>;
}
