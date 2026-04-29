use http::StatusCode;
use salvo::{Depot, Response, Router, handler};
use sea_orm::ConnectionTrait;
use serde::Serialize;

use crate::{
    boot::AppState,
    infrastructure::config::{HealthConfig, ServerConfig},
    web::controllers::response::{app_state, render_app_error, render_json},
};

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub checks: HealthChecksResponse,
}

#[derive(Debug, Serialize, Default)]
pub struct HealthChecksResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<HealthCheckResult>,
}

#[derive(Debug, Serialize)]
pub struct HealthCheckResult {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub fn router(config: &HealthConfig) -> Router {
    Router::with_path(config.route.trim_start_matches('/')).get(health_handler)
}

#[handler]
async fn health_handler(depot: &mut Depot, res: &mut Response) {
    let state = match app_state(depot) {
        Ok(state) => state,
        Err(error) => {
            render_app_error(res, error);
            return;
        }
    };
    let mut ok = true;
    let mut checks = HealthChecksResponse::default();

    if state.context().health_checks().database {
        let result = check_database(&state).await;
        if result.status != "ok" {
            ok = false;
        }
        checks.database = Some(result);
    }

    let body = HealthResponse {
        status: if ok { "ok" } else { "error" },
        checks,
    };

    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    render_json(res, status, body);
}

async fn check_database(state: &AppState) -> HealthCheckResult {
    match state.resources().db().execute_unprepared("SELECT 1").await {
        Ok(_) => HealthCheckResult {
            status: "ok",
            detail: None,
        },
        Err(_) => HealthCheckResult {
            status: "error",
            detail: None,
        },
    }
}

pub fn bind_address(health: &HealthConfig, server: &ServerConfig) -> String {
    let binding = health
        .server
        .binding
        .as_deref()
        .unwrap_or(server.binding.as_str());
    format!("{}:{}", binding, health.server.port)
}

pub fn shares_listener(health: &HealthConfig, server: &ServerConfig) -> bool {
    bind_address(health, server) == format!("{}:{}", server.binding, server.port)
}

#[cfg(test)]
mod tests {
    use super::{bind_address, shares_listener};
    use identity_infrastructure::config::{
        HealthChecksConfig, HealthConfig, HealthServerConfig, ServerConfig,
    };

    fn server() -> ServerConfig {
        ServerConfig {
            port: 5150,
            binding: "127.0.0.1".to_owned(),
            host: None,
        }
    }

    #[test]
    fn bind_address_falls_back_to_main_server_binding() {
        let health = HealthConfig {
            enable: true,
            route: "/health".to_owned(),
            server: HealthServerConfig {
                binding: None,
                port: 8081,
            },
            checks: HealthChecksConfig { database: true },
        };

        assert_eq!(bind_address(&health, &server()), "127.0.0.1:8081");
    }

    #[test]
    fn shares_listener_detects_matching_listener_configuration() {
        let server = server();
        let health = HealthConfig {
            enable: true,
            route: "/health".to_owned(),
            server: HealthServerConfig {
                binding: Some("127.0.0.1".to_owned()),
                port: 5150,
            },
            checks: HealthChecksConfig { database: true },
        };

        assert!(shares_listener(&health, &server));
    }

    #[test]
    fn shares_listener_detects_separate_listener_configuration() {
        let server = server();
        let health = HealthConfig {
            enable: true,
            route: "/health".to_owned(),
            server: HealthServerConfig {
                binding: Some("0.0.0.0".to_owned()),
                port: 8081,
            },
            checks: HealthChecksConfig { database: true },
        };

        assert!(!shares_listener(&health, &server));
    }
}
