use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ScopeDescription {
    pub code: String,
    pub name: String,
    pub names: BTreeMap<String, String>,
    pub description: String,
    /// BCP 47 language tag to consent description.
    pub descriptions: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
#[error("failed to load scope descriptions: {0}")]
pub struct ScopeCatalogError(pub String);

#[async_trait::async_trait]
pub trait ScopeCatalogRepository: Send + Sync {
    async fn list_names(&self) -> Result<Vec<String>, ScopeCatalogError>;
    async fn find_by_names(
        &self,
        names: &[&str],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError>;

    /// Names available to an access token aimed at `resources`. Protocol scopes
    /// (`resource_id IS NULL`) are global; API scopes are included only when
    /// owned by one of the targets. In-memory adapters may fall back to the
    /// global list.
    async fn list_names_for_resources(
        &self,
        _resources: &[String],
    ) -> Result<Vec<String>, ScopeCatalogError> {
        self.list_names().await
    }

    /// Resource-aware consent/display descriptions. A same-code scope in another
    /// resource must not describe the target scope.
    async fn find_by_names_for_resources(
        &self,
        names: &[&str],
        _resources: &[String],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError> {
        self.find_by_names(names).await
    }
}
