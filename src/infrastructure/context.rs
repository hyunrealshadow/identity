use crate::config::{AppEnvironment, HealthChecksConfig};

#[derive(Clone)]
pub struct AppContext {
    environment: AppEnvironment,
    health_checks: HealthChecksConfig,
}

impl AppContext {
    pub fn new(environment: AppEnvironment, health_checks: HealthChecksConfig) -> Self {
        Self {
            environment,
            health_checks,
        }
    }

    #[must_use]
    pub fn environment(&self) -> &AppEnvironment {
        &self.environment
    }

    #[must_use]
    pub fn is_production(&self) -> bool {
        self.environment.is_production()
    }

    #[must_use]
    #[cfg(feature = "oidc-conformance")]
    pub fn is_conformance(&self) -> bool {
        self.environment.is_conformance()
    }

    #[must_use]
    pub fn health_checks(&self) -> &HealthChecksConfig {
        &self.health_checks
    }
}
