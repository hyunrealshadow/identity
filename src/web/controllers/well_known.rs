use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::get};
use josekit::jwk::Jwk;
use serde::Serialize;

use crate::{
    application::error::AppError, boot::AppState, domain::key::model::KeyData,
    infrastructure::crypto::key::public_jwk_from_private_key_pem,
};

use super::response::AppJson;

#[derive(Debug, Clone, Serialize)]
pub struct JsonWebKeySetResponse {
    keys: Vec<Jwk>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/.well-known/keys", get(keys))
}

#[axum::debug_handler]
async fn keys(State(ctx): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let keys = match ctx.services().key().list_available().await {
        Ok(keys) => keys,
        Err(error) => {
            return super::response::error_response_from_headers(
                ctx.resources().i18n(),
                &headers,
                error,
            );
        }
    }
    .into_iter()
    .filter_map(|key| match key.data {
        KeyData::Asymmetric(data) => Some((key.oid, data.private_key)),
        KeyData::Symmetric(_) => None,
    })
    .map(|(oid, private_key)| public_jwk_from_private_key_pem(&private_key, Some(&oid.to_string())))
    .collect::<Result<Vec<_>, _>>()
    .map_err(AppError::from);

    let keys = match keys {
        Ok(keys) => keys,
        Err(error) => {
            return super::response::error_response_from_headers(
                ctx.resources().i18n(),
                &headers,
                error,
            );
        }
    };

    let response = JsonWebKeySetResponse { keys };

    AppJson(response).into_response()
}
