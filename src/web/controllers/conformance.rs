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
    key_id: String,
    algorithm: String,
}

#[handler]
async fn rotate_keys(depot: &mut Depot, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let key = ctx
        .services()
        .key()
        .generate_and_store(GenerateAsymmetricKeyInput {
            algorithm: AsymmetricKeyAlgorithm::Rsa2048,
            certificate: None,
        })
        .await?;

    let key_id =
        identity_domain::global_id::encode::<identity_domain::global_id::kind::Key>(key.oid);
    render_json(
        res,
        StatusCode::OK,
        RotateKeysResponse {
            key_id,
            algorithm: "RS256".to_owned(),
        },
    );
    Ok(())
}
