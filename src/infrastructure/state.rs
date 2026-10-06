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
    pub fn settings(&self) -> &AppRuntimeSettings {
        self.settings.as_ref()
    }

    #[must_use]
    pub fn services(&self) -> &AppServices {
        self.services.as_ref()
    }
}
