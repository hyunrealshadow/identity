use std::sync::Arc;

use super::{
    context::AppContext, lifecycle::AppLifecycle, resources::AppResources, services::AppServices,
    settings::AppRuntimeSettings,
};

#[derive(Clone)]
pub struct AppState {
    context: Arc<AppContext>,
    resources: Arc<AppResources>,
    lifecycle: Arc<AppLifecycle>,
    settings: Arc<AppRuntimeSettings>,
    services: Arc<AppServices>,
}

impl AppState {
    pub fn new(
        context: Arc<AppContext>,
        resources: Arc<AppResources>,
        lifecycle: Arc<AppLifecycle>,
        settings: Arc<AppRuntimeSettings>,
        services: Arc<AppServices>,
    ) -> Self {
        Self {
            context,
            resources,
            lifecycle,
            settings,
            services,
        }
    }

    #[must_use]
    pub fn context(&self) -> &AppContext {
        self.context.as_ref()
    }

    #[must_use]
    pub fn resources(&self) -> &AppResources {
        self.resources.as_ref()
    }

    #[must_use]
    pub fn lifecycle(&self) -> &AppLifecycle {
        self.lifecycle.as_ref()
    }

    #[must_use]
    pub(crate) fn settings(&self) -> &AppRuntimeSettings {
        self.settings.as_ref()
    }

    /// Whether `origin` is permitted by the cached application/CORS allowlist.
    #[must_use]
    pub fn allows_cors_origin(&self, origin: &str) -> bool {
        self.settings.cors_origins().allows(origin)
    }

    #[must_use]
    pub fn services(&self) -> &AppServices {
        self.services.as_ref()
    }
}
