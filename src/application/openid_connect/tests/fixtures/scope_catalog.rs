use identity_domain::openid_connect::scope_catalog::{
    ScopeCatalogError, ScopeCatalogRepository, ScopeDescription,
};

pub(crate) struct TestScopeCatalog(pub Vec<String>);

#[async_trait::async_trait]
impl ScopeCatalogRepository for TestScopeCatalog {
    async fn list_names(&self) -> Result<Vec<String>, ScopeCatalogError> {
        Ok(self.0.clone())
    }

    async fn find_by_names(
        &self,
        names: &[&str],
    ) -> Result<Vec<ScopeDescription>, ScopeCatalogError> {
        Ok(self
            .0
            .iter()
            .filter(|name| names.contains(&name.as_str()))
            .map(|name| ScopeDescription {
                name: name.clone(),
                display_name: name.clone(),
                description: name.clone(),
                descriptions: Default::default(),
            })
            .collect())
    }
}
