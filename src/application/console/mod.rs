use std::sync::Arc;

use identity_domain::client::built_in::CONSOLE_CLIENT_NAME;
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
    pub client_id: String,
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
        let (Some(login), Some(console), Some(client_id)) =
            (app.login_domain, app.console_domain, app.console_client_id)
        else {
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
            client_id: client_id.to_string(),
            redirect_uri: endpoint(&console, "callback")?,
            post_logout_redirect_uri: endpoint(&console, "signed-out")?,
            account_url: endpoint(&login, "account")?,
            scope: "openid profile email management.*",
            display_name: CONSOLE_CLIENT_NAME,
            environment: environment.to_owned(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setting::SettingsSnapshot;
    use uuid::Uuid;

    #[test]
    fn runtime_requires_and_uses_the_installed_console_identity() {
        let mut app = AppSettings {
            domain: Some("https://identity.example.test".to_owned()),
            login_domain: Some("https://account.example.test".to_owned()),
            console_domain: Some("https://console.example.test/console/".to_owned()),
            ..Default::default()
        };
        let runtime = |app: &AppSettings| {
            ConsoleRuntimeService::new(Arc::new(
                SettingsSnapshot::default()
                    .with_section(app)
                    .with_section(&InstallationSettings {
                        initialized: true,
                        ..Default::default()
                    }),
            ))
            .runtime_config("test")
            .unwrap()
        };
        assert!(runtime(&app).is_none());
        for _ in 0..2 {
            let oid = Uuid::new_v4();
            app.console_client_id = Some(oid);
            assert_eq!(runtime(&app).unwrap().client_id, oid.to_string());
        }
    }
}
