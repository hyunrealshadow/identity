use std::sync::Arc;

use identity_domain::client::built_in::{CONSOLE_CLIENT_NAME, CONSOLE_CLIENT_OID};
use serde::Serialize;
use url::Url;

use crate::{
    error::AppError,
    setting::{AppSettings, InstallationSettings, SettingsSource},
};

/// Browser-visible configuration only. Workload credentials never enter this value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleRuntimeConfiguration {
    pub issuer: String,
    pub graphql_url: String,
    pub client_id: &'static str,
    pub redirect_uri: String,
    pub post_logout_redirect_uri: String,
    pub account_url: String,
    pub scope: &'static str,
    pub display_name: &'static str,
    pub environment: String,
}

pub struct ConsoleRuntimeService {
    settings: Arc<dyn SettingsSource>,
}

impl ConsoleRuntimeService {
    pub fn new(settings: Arc<dyn SettingsSource>) -> Self {
        Self { settings }
    }

    #[tracing::instrument(skip_all, name = "console.runtime_configuration")]
    pub fn runtime_config(
        &self,
        environment: &str,
    ) -> Result<Option<ConsoleRuntimeConfiguration>, AppError> {
        let snapshot = self.settings.snapshot();
        let app = snapshot.section::<AppSettings>();
        let (Some(login), Some(console)) = (app.login_domain, app.console_domain) else {
            return Ok(None);
        };
        let issuer = crate::openid_connect::provider::normalize_issuer(
            &snapshot.section::<InstallationSettings>(),
            app.domain.as_deref(),
        )?;
        let endpoint = |base: &str, path: &str| -> Result<String, AppError> {
            let base = Url::parse(&format!("{}/", base.trim_end_matches('/')))
                .map_err(AppError::internal)?;
            base.join(path)
                .map(String::from)
                .map_err(AppError::internal)
        };
        Ok(Some(ConsoleRuntimeConfiguration {
            issuer: issuer.to_string(),
            graphql_url: endpoint(issuer.as_str(), "graphql")?,
            client_id: CONSOLE_CLIENT_OID,
            redirect_uri: endpoint(&console, "callback")?,
            post_logout_redirect_uri: endpoint(&console, "signed-out")?,
            account_url: endpoint(&login, "account")?,
            scope: "openid profile email management.*",
            display_name: CONSOLE_CLIENT_NAME,
            environment: environment.to_owned(),
        }))
    }
}
