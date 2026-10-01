use http::StatusCode;
use salvo::{Depot, Request, Response, Router, handler};
use serde::Serialize;

use crate::{
    application::error::AppError, application::openid_connect::provider::OpenIdProviderService,
    domain::key::PublicJwk,
};

use super::response::{JsonWebResult, app_state, render_json};
use crate::cors::{ClientCors, preflight};

#[derive(Debug, Clone, Serialize)]
pub struct JsonWebKeySetResponse {
    keys: Vec<PublicJwk>,
}

pub fn routes() -> Router {
    Router::new()
        .push(
            Router::with_path(".well-known/openid-configuration")
                .hoop(ClientCors::new("GET"))
                .get(openid_configuration)
                .options(preflight),
        )
        .push(
            Router::with_path(".well-known/oauth-authorization-server")
                .hoop(ClientCors::new("GET"))
                .get(authorization_server_metadata)
                .options(preflight),
        )
        .push(
            Router::with_path(".well-known/oauth-authorization-server/{**issuer_path}")
                .hoop(ClientCors::new("GET"))
                .get(authorization_server_metadata)
                .options(preflight),
        )
        .push(
            Router::with_path(".well-known/keys")
                .hoop(ClientCors::new("GET"))
                .get(keys_handler)
                .options(preflight),
        )
}

async fn openid_configuration_document(
    service: &OpenIdProviderService,
) -> Result<identity_domain::openid_connect::OpenIdProviderMetadata, AppError> {
    service.discovery_metadata().await
}

#[handler]
async fn openid_configuration(depot: &mut Depot, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let metadata = openid_configuration_document(ctx.services().oidc()).await?;
    render_json(res, StatusCode::OK, metadata);
    Ok(())
}

#[handler]
async fn authorization_server_metadata(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let issuer = ctx.services().oidc().issuer()?;
    // RFC 8414 inserts the well-known suffix before the issuer path.
    let requested_path = req.param::<String>("issuer_path").unwrap_or_default();
    if requested_path != issuer.path().trim_matches('/') {
        res.status_code(StatusCode::NOT_FOUND);
        return Ok(());
    }
    let metadata = authorization_server_document(ctx.services().oidc().discovery_metadata().await?);
    render_json(res, StatusCode::OK, metadata);
    Ok(())
}

fn authorization_server_document(
    oidc: identity_domain::openid_connect::OpenIdProviderMetadata,
) -> serde_json::Value {
    let metadata = serde_json::json!({
        "issuer": oidc.issuer,
        "authorization_endpoint": oidc.authorization_endpoint,
        "token_endpoint": oidc.token_endpoint,
        "jwks_uri": oidc.jwks_uri,
        "scopes_supported": oidc.scopes_supported,
        "response_types_supported": oidc.response_types_supported,
        "response_modes_supported": oidc.response_modes_supported,
        "grant_types_supported": oidc.grant_types_supported,
        "token_endpoint_auth_methods_supported": oidc.token_endpoint_auth_methods_supported,
        "token_endpoint_auth_signing_alg_values_supported": oidc.token_endpoint_auth_signing_alg_values_supported,
        "revocation_endpoint": oidc.revocation_endpoint,
        "revocation_endpoint_auth_methods_supported": oidc.revocation_endpoint_auth_methods_supported,
        "revocation_endpoint_auth_signing_alg_values_supported": oidc.revocation_endpoint_auth_signing_alg_values_supported,
        "introspection_endpoint": oidc.introspection_endpoint,
        "introspection_endpoint_auth_methods_supported": oidc.introspection_endpoint_auth_methods_supported,
        "introspection_endpoint_auth_signing_alg_values_supported": oidc.introspection_endpoint_auth_signing_alg_values_supported,
        "registration_endpoint": oidc.registration_endpoint,
        "device_authorization_endpoint": oidc.device_authorization_endpoint,
        "code_challenge_methods_supported": oidc.code_challenge_methods_supported,
        "service_documentation": oidc.service_documentation,
        "ui_locales_supported": oidc.ui_locales_supported,
        "op_policy_uri": oidc.op_policy_uri,
        "op_tos_uri": oidc.op_tos_uri
    });
    let mut metadata = metadata;
    if let Some(object) = metadata.as_object_mut() {
        object.retain(|_, value| !value.is_null() && !value.as_array().is_some_and(Vec::is_empty));
    }
    metadata
}

#[handler]
async fn keys_handler(depot: &mut Depot, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let key_jwks = ctx.services().key().list_available_jwks().await?;
    let keys: Vec<PublicJwk> = key_jwks.into_iter().map(|binding| binding.jwk).collect();

    let response = JsonWebKeySetResponse { keys };

    render_json(res, StatusCode::OK, response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        application::openid_connect::provider::OpenIdProviderService,
        application::setting::{AppSettings, InstallationSettings, SettingsSnapshot},
    };

    use super::openid_configuration_document;

    struct TestInstallationSetting(Arc<SettingsSnapshot>);

    impl identity_application::setting::SettingsSource for TestInstallationSetting {
        fn snapshot(&self) -> Arc<identity_application::setting::SettingsSnapshot> {
            Arc::clone(&self.0)
        }
    }

    #[tokio::test]
    async fn discovery_contract_contains_expected_fields() {
        let service = OpenIdProviderService::new(Arc::new(TestInstallationSetting(Arc::new(
            SettingsSnapshot::default()
                .with_section(&AppSettings {
                    domain: Some("identity.example.com".to_owned()),
                    login_domain: None,
                    login_client_id: None,
                })
                .with_section(&InstallationSettings {
                    initialized: true,
                    initialized_at: None,
                }),
        ))));

        let metadata = openid_configuration_document(&service).await.unwrap();
        let json = serde_json::to_value(metadata).unwrap();

        assert_eq!(json["issuer"], "https://identity.example.com/");
        assert_eq!(
            json["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            json["authorization_endpoint"],
            "https://identity.example.com/oauth2/authorize"
        );
        assert_eq!(
            json["token_endpoint"],
            "https://identity.example.com/oauth2/token"
        );
        assert_eq!(
            json["revocation_endpoint"],
            "https://identity.example.com/oauth2/revoke"
        );
        assert_eq!(
            json["jwks_uri"],
            "https://identity.example.com/.well-known/keys"
        );
        assert_eq!(
            json["end_session_endpoint"],
            "https://identity.example.com/oauth2/logout"
        );
        assert_eq!(
            json["check_session_iframe"],
            "https://identity.example.com/oauth2/check_session"
        );
        assert!(json.get("registration_endpoint").is_none());
        assert_eq!(json["frontchannel_logout_supported"], true);
        assert_eq!(json["frontchannel_logout_session_supported"], true);
        assert_eq!(json["backchannel_logout_supported"], true);
        assert_eq!(json["backchannel_logout_session_supported"], true);
        assert_eq!(json["claims_parameter_supported"], true);
        assert_eq!(json["request_parameter_supported"], true);
        assert_eq!(json["request_uri_parameter_supported"], true);
        assert_eq!(json["require_request_uri_registration"], true);
        assert_eq!(
            json["acr_values_supported"],
            serde_json::json!([
                identity_domain::auth::ACR_AAL1,
                identity_domain::auth::ACR_AAL2
            ])
        );
        assert!(
            json["response_modes_supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("form_post"))
        );
        assert_eq!(
            json["subject_types_supported"],
            serde_json::json!(["public", "pairwise"])
        );
        assert_eq!(
            json["id_token_signing_alg_values_supported"],
            if cfg!(feature = "allow-none-alg") {
                serde_json::json!(["ES256", "none"])
            } else {
                serde_json::json!(["ES256"])
            }
        );
    }
}
#[cfg(test)]
mod authorization_metadata_tests {
    use http::StatusCode;
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };
    #[tokio::test]
    async fn metadata_route_publishes_oauth_endpoints_and_omits_unset_fields() {
        let state = identity_infrastructure::test_app_state_with_cors_origin(None).await;
        let service = Service::new(super::routes().hoop(salvo::affix_state::inject(state)));
        let mut response =
            TestClient::get("http://127.0.0.1:5800/.well-known/oauth-authorization-server")
                .send(&service)
                .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let json: serde_json::Value =
            serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
        assert!(
            json["introspection_endpoint"]
                .as_str()
                .unwrap()
                .ends_with("/oauth2/introspect")
        );
        assert!(
            json["revocation_endpoint"]
                .as_str()
                .unwrap()
                .ends_with("/oauth2/revoke")
        );
        assert_eq!(
            json["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert!(
            !json["introspection_endpoint_auth_methods_supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("none"))
        );
        assert!(json.get("registration_endpoint").is_none());
        assert!(json.get("id_token_signing_alg_values_supported").is_none());
        let response =
            TestClient::get("http://127.0.0.1:5800/.well-known/oauth-authorization-server/wrong")
                .send(&service)
                .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    }
}
