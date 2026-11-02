use http::StatusCode;
use identity_domain::openid_connect::OpenIdProviderMetadata;
use salvo::{Depot, Request, Response, Router, handler};
use serde::Serialize;
use serde_json::{Value, json};

use super::response::{JsonWebResult, app_state, render_json};
use crate::{
    application::{error::AppError, openid_connect::provider::OpenIdProviderService},
    cors::{ClientCors, preflight},
    domain::key::PublicJwk,
};

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
) -> Result<OpenIdProviderMetadata, AppError> {
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

fn authorization_server_document(oidc: OpenIdProviderMetadata) -> Value {
    let metadata = json!({
        "issuer": oidc.issuer,
        "authorization_endpoint": oidc.authorization_endpoint,
        "token_endpoint": oidc.token_endpoint,
        "pushed_authorization_request_endpoint": oidc.pushed_authorization_request_endpoint,
        "require_pushed_authorization_requests": oidc.require_pushed_authorization_requests,
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
