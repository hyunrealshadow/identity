use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct ErrorParams {
    inner: BTreeMap<&'static str, String>,
}

impl ErrorParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.inner.insert(key, value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.inner.get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.inner.iter().map(|(key, value)| (*key, value.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
