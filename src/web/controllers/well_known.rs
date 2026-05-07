use http::StatusCode;
use josekit::jwk::Jwk;
use salvo::{Depot, Response, Router, handler};
use serde::Serialize;

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    application::openid_connect::provider::OpenIdProviderService,
};

use super::response::{app_state, render_json};

#[derive(Debug, Clone, Serialize)]
pub struct JsonWebKeySetResponse {
    keys: Vec<Jwk>,
}

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path(".well-known/openid-configuration").get(openid_configuration))
        .push(Router::with_path(".well-known/keys").get(keys_handler))
}

async fn openid_configuration_document(
    service: &OpenIdProviderService,
) -> Result<identity_domain::openid_connect::OpenIdProviderMetadata, AppError> {
    service.discovery_metadata().await
}

#[handler]
async fn openid_configuration(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let ctx = app_state(depot)?;
    let metadata = openid_configuration_document(ctx.services().oidc()).await?;
    render_json(res, StatusCode::OK, metadata);
    Ok(())
}

#[handler]
async fn keys_handler(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let ctx = app_state(depot)?;
    let key_jwks = ctx.services().key().list_available_jwks().await?;
    let keys: Vec<Jwk> = key_jwks
        .into_iter()
        .map(|binding| {
            serde_json::from_value(binding.jwk).map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })
        })
        .collect::<Result<_, _>>()?;

    let response = JsonWebKeySetResponse { keys };

    render_json(res, StatusCode::OK, response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        application::openid_connect::provider::OpenIdProviderService,
        domain::setting::installation::{InstallationSetting, InstallationState},
    };

    use super::openid_configuration_document;

    struct TestInstallationSetting(Arc<InstallationState>);

    impl identity_application::setting::runtime::SettingProvider<InstallationSetting>
        for TestInstallationSetting
    {
        fn current_value(&self) -> Arc<InstallationState> {
            Arc::clone(&self.0)
        }
    }

    #[tokio::test]
    async fn openid_configuration_returns_provider_metadata() {
        let service = OpenIdProviderService::new(Arc::new(TestInstallationSetting(Arc::new(
            InstallationState {
                initialized: true,
                domain: Some("identity.example.com".to_owned()),
                first_user_oid: None,
                first_key_oid: None,
                initialized_at: None,
            },
        ))));

        let metadata = openid_configuration_document(&service).await.unwrap();

        assert_eq!(metadata.issuer.as_str(), "https://identity.example.com/");
        assert_eq!(
            metadata.authorization_endpoint.as_str(),
            "https://identity.example.com/oauth2/authorize"
        );
        assert_eq!(
            metadata.jwks_uri.as_str(),
            "https://identity.example.com/.well-known/keys"
        );
    }

    #[tokio::test]
    async fn discovery_contract_contains_expected_fields() {
        let service = OpenIdProviderService::new(Arc::new(TestInstallationSetting(Arc::new(
            InstallationState {
                initialized: true,
                domain: Some("identity.example.com".to_owned()),
                first_user_oid: None,
                first_key_oid: None,
                initialized_at: None,
            },
        ))));

        let metadata = openid_configuration_document(&service).await.unwrap();
        let json = serde_json::to_value(metadata).unwrap();

        assert_eq!(json["issuer"], "https://identity.example.com/");
        assert_eq!(
            json["token_endpoint"],
            "https://identity.example.com/oauth2/token"
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
        assert!(json.get("frontchannel_logout_supported").is_none());
        assert!(json.get("backchannel_logout_supported").is_none());
        assert_eq!(json["claims_parameter_supported"], true);
        assert_eq!(json["request_parameter_supported"], true);
        assert_eq!(json["request_uri_parameter_supported"], true);
        assert_eq!(json["require_request_uri_registration"], false);
        assert_eq!(json["acr_values_supported"], serde_json::json!(["1"]));
        assert_eq!(
            json["subject_types_supported"],
            serde_json::json!(["public", "pairwise"])
        );
        assert_eq!(
            json["id_token_signing_alg_values_supported"],
            serde_json::json!(["ES256"])
        );
    }
}
