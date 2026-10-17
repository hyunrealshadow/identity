//! Conformance-only key rotation endpoint.
//!
//! Mounted only with `oidc-conformance` and `APP_ENV=conformance`.
//! Browser authentication and consent use the standard Login application.

use http::StatusCode;
use identity_application::key::asymmetric::GenerateAsymmetricKeyInput;
use identity_domain::key::model::AsymmetricKeyAlgorithm;
use salvo::{Depot, Response, Router, handler};
use serde::Serialize;
use uuid::Uuid;

use super::response::{JsonWebResult, app_state, render_json};

pub fn routes() -> Router {
    Router::with_path("conformance/rotate-keys").post(rotate_keys)
}

#[derive(Debug, Serialize)]
struct RotateKeysResponse {
    key_oid: String,
    algorithm: String,
}

#[handler]
async fn rotate_keys(depot: &mut Depot, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let key = ctx
        .services()
        .key()
        .generate_and_store(GenerateAsymmetricKeyInput {
            algorithm: AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
            certificate: None,
        })
        .await?;

    let key_oid = Uuid::from(key.oid).to_string();
    render_json(
        res,
        StatusCode::OK,
        RotateKeysResponse {
            key_oid,
            algorithm: "RS256".to_owned(),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use salvo::{Service, test::TestClient};

    use super::routes;

    #[tokio::test]
    async fn authentication_bypass_routes_are_not_exposed() {
        let service = Service::new(routes());
        for route in ["auto-login", "auto-consent"] {
            let url = format!("http://127.0.0.1:5800/conformance/{route}");
            let get = TestClient::get(&url).send(&service).await;
            let post = TestClient::post(&url).send(&service).await;
            assert_eq!(get.status_code, Some(StatusCode::NOT_FOUND));
            assert_eq!(post.status_code, Some(StatusCode::NOT_FOUND));
        }
    }
}
