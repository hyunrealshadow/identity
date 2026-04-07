use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct InstallAlgorithmOption {
    pub value: &'static str,
    pub label: &'static str,
    pub selected: bool,
}

#[derive(Debug, Serialize)]
pub struct InstallPageData {
    pub username: String,
    pub email: String,
    pub domain: String,
    pub error: Option<String>,
    pub csrf_token: String,
    pub algorithms: Vec<InstallAlgorithmOption>,
}
